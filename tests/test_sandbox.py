"""Policy unit tests use synthetic Docker/tool responses, not real isolation results."""

import json
import sys

import pytest
from conftest import archive

from sentinel import sandbox
from sentinel.ingestion import ingest_zip
from sentinel.sandbox import (
    DockerAnalyzer,
    ExecutionLimit,
    SandboxUnavailable,
    container_command,
    validate_engine,
)

IMAGE = "sha256:" + "a" * 64
ENGINE = {
    "SecurityOptions": ["name=rootless", "name=seccomp,profile=builtin"],
    "OSType": "linux",
    "CgroupVersion": "2",
    "MemoryLimit": True,
    "SwapLimit": True,
    "PidsLimit": True,
    "CpuCfsQuota": True,
}


def test_disabled_does_not_invoke_docker(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Disabled analyzer must never invoke Docker")

    monkeypatch.setattr(sandbox, "_docker", forbidden)
    manifest, snapshot = ingest_zip(archive({"A.sol": "contract A {}"}), tmp_path)
    result = DockerAnalyzer("slither").run(manifest, snapshot)
    assert result.status == "unavailable"
    assert not result.findings


@pytest.mark.parametrize(
    "field,value",
    [
        ("SecurityOptions", ["name=seccomp,profile=builtin"]),
        ("SecurityOptions", ["name=rootless", "name=seccomp,profile=unconfined"]),
        ("CgroupVersion", "1"),
        ("OSType", "windows"),
        ("MemoryLimit", False),
        ("SwapLimit", False),
        ("PidsLimit", False),
        ("CpuCfsQuota", False),
    ],
)
def test_engine_policy_rejects_missing_isolation(field, value):
    info = {**ENGINE, field: value}
    with pytest.raises(SandboxUnavailable):
        validate_engine(info)


def test_command_controls_and_immutable_image(tmp_path):
    validate_engine(ENGINE)
    args = container_command(IMAGE, tmp_path, "slither", "test-name")
    for required in (
        "--network=none",
        "--read-only",
        "--user=65532:65532",
        "--cap-drop=ALL",
        "--memory=512m",
        "--memory-swap=512m",
        "--pids-limit=64",
        "--pull=never",
        "--security-opt=no-new-privileges:true",
    ):
        assert required in args
    assert "privileged" not in " ".join(args)
    assert "docker.sock" not in " ".join(args)
    assert f"type=bind,src={tmp_path},dst=/src,readonly" in args
    with pytest.raises(SandboxUnavailable):
        container_command("toolchain:latest", tmp_path, "slither", "bad")
    with pytest.raises(SandboxUnavailable):
        container_command(IMAGE, tmp_path, "bash", "bad")


def test_synthetic_tool_output_is_parsed_and_cleanup_runs(tmp_path, monkeypatch):
    manifest, snapshot = ingest_zip(archive({"A.sol": "contract A {}"}), tmp_path)
    calls = []

    def fake(arguments, timeout=8):
        calls.append(arguments)
        if arguments[0] == "info":
            return 0, json.dumps(ENGINE)
        if arguments[0] == "rm":
            return 0, ""
        assert arguments[0] == "run"
        return 0, json.dumps(
            {
                "tool": "semgrep",
                "version": "synthetic-test-version",
                "executions": [{"stdout": '{"results":[]}', "stderr": "", "returncode": 0}],
            }
        )

    monkeypatch.setattr(sandbox, "_docker", fake)
    result = DockerAnalyzer("semgrep", IMAGE, enabled=True).run(manifest, snapshot)
    assert result.status == "completed"
    assert IMAGE in result.raw
    assert calls[-1][0] == "rm"


def test_output_timeout_is_failure_and_forces_cleanup(tmp_path, monkeypatch):
    manifest, snapshot = ingest_zip(archive({"A.sol": "contract A {}"}), tmp_path)
    calls = []

    def fake(arguments, timeout=8):
        calls.append(arguments)
        if arguments[0] == "info":
            return 0, json.dumps(ENGINE)
        if arguments[0] == "run":
            raise ExecutionLimit("budget exhausted")
        return 0, ""

    monkeypatch.setattr(sandbox, "_docker", fake)
    result = DockerAnalyzer("slither", IMAGE, enabled=True).run(manifest, snapshot)
    assert result.status == "failed"
    assert calls[-1][0] == "rm"


def test_unavailable_engine_does_not_run_source(tmp_path, monkeypatch):
    manifest, snapshot = ingest_zip(archive({"A.sol": "contract A {}"}), tmp_path)
    calls = []

    def fake(arguments, timeout=8):
        calls.append(arguments)
        raise ExecutionLimit("daemon timeout")

    monkeypatch.setattr(sandbox, "_docker", fake)
    assert (
        DockerAnalyzer("slither", IMAGE, enabled=True).run(manifest, snapshot).status
        == "unavailable"
    )
    assert len(calls) == 1


def test_bounded_process_output_and_timeout(monkeypatch):
    # Trusted Python test snippets exercise pipe budgets. No repository code executes here.
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: sys.executable)
    code, text = sandbox._docker(["-c", "print('bounded')"])
    assert code == 0 and text.strip() == "bounded"
    with pytest.raises(ExecutionLimit):
        sandbox._docker(["-c", "import time; time.sleep(1)"], timeout=0.05)
    monkeypatch.setattr(sandbox, "MAX_OUTPUT", 16)
    with pytest.raises(ExecutionLimit):
        sandbox._docker(["-c", "print('x' * 64)"])
