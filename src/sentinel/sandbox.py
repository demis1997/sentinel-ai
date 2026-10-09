"""Fail-closed source-only analyzers. Only the trusted Docker CLI runs on the host."""

import json
import os
import re
import selectors
import shutil

# Only the trusted Docker CLI executes on the host; never a shell.
import subprocess  # nosec B404
import tempfile
from pathlib import Path
from time import monotonic
from typing import Any, Literal
from uuid import uuid4

from sentinel.analysis import parse_semgrep, parse_slither
from sentinel.domain import AnalyzerResult, Manifest, StrictModel
from sentinel.ingestion import verify_snapshot

MAX_OUTPUT = 2 * 1024 * 1024


class SandboxUnavailable(RuntimeError):
    pass


class ExecutionLimit(RuntimeError):
    pass


class ToolExecution(StrictModel):
    stdout: str
    stderr: str
    returncode: int


class ToolEnvelope(StrictModel):
    tool: Literal["slither", "semgrep"]
    version: str
    executions: list[ToolExecution]


def validate_engine(info: dict[str, Any]) -> None:
    options = info.get("SecurityOptions", [])
    if not any(option == "name=rootless" for option in options):
        raise SandboxUnavailable("Rootless Docker is required by this initial policy")
    if not any(
        option.startswith("name=seccomp,profile=") and "unconfined" not in option
        for option in options
    ):
        raise SandboxUnavailable("A confined seccomp profile is required")
    if info.get("OSType") != "linux" or info.get("CgroupVersion") != "2":
        raise SandboxUnavailable("Linux cgroup v2 is required")
    for resource in ("MemoryLimit", "SwapLimit", "PidsLimit", "CpuCfsQuota"):
        if info.get(resource) is not True:
            raise SandboxUnavailable(f"Required resource control unavailable: {resource}")


def container_command(image: str, source: Path, tool: str, name: str) -> list[str]:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise SandboxUnavailable("Use an immutable local image ID, never a mutable tag")
    if tool not in {"slither", "semgrep"}:
        raise SandboxUnavailable("Tool not allowed")
    if "," in str(source) or not source.is_absolute() or source.is_symlink():
        raise SandboxUnavailable("Unsafe source mount")
    return [
        "run",
        "--rm",
        "--pull=never",
        "--name",
        name,
        "--network=none",
        "--read-only",
        "--user=65532:65532",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--cpus=1",
        "--memory=512m",
        "--memory-swap=512m",
        "--pids-limit=64",
        "--ulimit=nofile=256:256",
        "--log-driver=none",
        "--ipc=none",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
        "--tmpfs=/work:rw,noexec,nosuid,nodev,size=128m,mode=1777",
        "--mount",
        f"type=bind,src={source},dst=/src,readonly",
        "--workdir=/work",
        "--env=HOME=/tmp",
        "--env=SEMGREP_SEND_METRICS=off",
        "--entrypoint=/usr/local/bin/python",
        image,
        "/opt/sentinel/analyze.py",
        tool,
    ]


def _docker(arguments: list[str], timeout: float = 8) -> tuple[int, str]:
    binary = shutil.which("docker")
    if binary is None:
        raise SandboxUnavailable("Docker CLI unavailable")
    # The executable is a trusted host CLI; arguments never contain a shell program.
    with subprocess.Popen(  # nosec B603
        [binary, *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ) as process:
        if process.stdout is None:
            raise SandboxUnavailable("Docker output pipe unavailable")
        chunks = bytearray()
        deadline = monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        raise ExecutionLimit("Docker execution timeout")
                    ready = selector.select(min(remaining, 0.2))
                    if not ready:
                        continue
                    data = os.read(process.stdout.fileno(), 65536)
                    if not data:
                        break
                    chunks.extend(data)
                    if len(chunks) > MAX_OUTPUT:
                        raise ExecutionLimit("Docker output budget exhausted")
            code = process.wait(timeout=max(0.01, deadline - monotonic()))
        except (ExecutionLimit, subprocess.TimeoutExpired):
            process.kill()
            process.wait()
            raise ExecutionLimit("Docker timeout or output budget exhausted") from None
    return code, chunks.decode("utf-8", errors="replace")


class DockerAnalyzer:
    def __init__(self, tool: str, image: str | None = None, enabled: bool = False) -> None:
        if tool not in {"slither", "semgrep"}:
            raise ValueError("Unsupported analyzer")
        self.tool = tool
        self.image = image
        self.enabled = enabled

    def run(self, manifest: Manifest, snapshot: Path) -> AnalyzerResult:
        if not self.enabled or not self.image:
            return self._unavailable("Sandbox has not passed operator isolation validation")
        try:
            code, raw_info = _docker(["info", "--format", "{{json .}}"])
            if code != 0:
                raise SandboxUnavailable("Docker daemon unavailable")
            validate_engine(json.loads(raw_info))
            # No build or pull occurs in the worker. Validate the image reference before any run.
            container_command(self.image, snapshot.resolve(), self.tool, "policy-check")
        except (SandboxUnavailable, ExecutionLimit, OSError, ValueError) as exc:
            return self._unavailable(str(exc))
        name = f"sentinel-analysis-{uuid4()}"
        result: AnalyzerResult
        try:
            verify_snapshot(manifest, snapshot)
            with tempfile.TemporaryDirectory(prefix="sentinel-analysis-") as directory:
                # Private parent; mounted child has sources only, with no host secrets or configs.
                source = Path(directory) / "source"
                source.mkdir(mode=0o755)
                for file in manifest.files:
                    if file.path.endswith(".sol"):
                        target = source / file.path
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes((snapshot / file.path).read_bytes())
                        target.chmod(0o444)
                code, raw = _docker(
                    container_command(self.image, source, self.tool, name), timeout=180
                )
                if code != 0:
                    raise ValueError("Sandbox process failed")
                envelope = ToolEnvelope.model_validate_json(raw)
                if envelope.tool != self.tool or not envelope.executions:
                    raise ValueError("Invalid sandbox tool envelope")
                parser = parse_slither if self.tool == "slither" else parse_semgrep
                findings = []
                errors = []
                for execution in envelope.executions:
                    parsed = parser(execution.stdout, manifest, envelope.version)
                    if self.tool == "semgrep" and execution.returncode != 0:
                        errors.append("Semgrep exited unsuccessfully")
                    if parsed.status != "completed":
                        errors.append(parsed.error or "Analyzer failed")
                    findings.extend(parsed.findings)
                result = AnalyzerResult(
                    tool=self.tool,
                    version=envelope.version,
                    status="failed" if errors else "completed",
                    findings=findings,
                    raw=json.dumps({"image_digest": self.image, "output": json.loads(raw)}),
                    error="; ".join(errors) if errors else None,
                )
        except (ValueError, OSError, ExecutionLimit) as exc:
            result = AnalyzerResult(
                tool=self.tool, version="unknown", status="failed", error=str(exc)
            )
        finally:
            try:
                code, _ = _docker(["rm", "--force", name])
                # --rm already removed successfully completed containers. A failed rm may also mean
                # it is gone; only a daemon connectivity failure leaves cleanup uncertain.
                if code != 0:
                    inspect_code, _ = _docker(["inspect", name])
                    if inspect_code == 0:
                        raise SandboxUnavailable("Container cleanup could not be established")
                    daemon_code, _ = _docker(["info", "--format", "{{json .ID}}"])
                    if daemon_code != 0:
                        raise SandboxUnavailable("Docker daemon unreachable during cleanup")
            except (OSError, ExecutionLimit, SandboxUnavailable) as exc:
                raise SandboxUnavailable("Container cleanup is uncertain; stop the worker") from exc
        return result

    def _unavailable(self, reason: str) -> AnalyzerResult:
        return AnalyzerResult(tool=self.tool, version="unknown", status="unavailable", error=reason)
