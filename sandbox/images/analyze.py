"""Trusted image entry point. Do not run this tool executor on the host."""

import json

# Fixed analyzer tools execute exclusively inside the container.
import subprocess  # nosec B404
import sys
from pathlib import Path


def execute(arguments: list[str]) -> dict[str, object]:
    # Only fixed tool executables run inside the isolated container. No shell or repository script.
    result = subprocess.run(  # nosec B603
        arguments,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}


def main() -> None:
    if not Path("/src").is_dir() or not Path("/opt/sentinel").is_dir():
        raise RuntimeError("Image-only entry point")
    tool = sys.argv[1]
    if tool == "semgrep":
        version = execute(["/usr/local/bin/semgrep", "--version"])["stdout"]
        executions = [
            execute(
                [
                    "/usr/local/bin/semgrep",
                    "scan",
                    "--config=/opt/sentinel/rules.yml",
                    "--json",
                    "--metrics=off",
                    "--disable-version-check",
                    "--no-git-ignore",
                    "/src",
                ]
            )
        ]
    elif tool == "slither":
        version = execute(["/usr/local/bin/slither", "--version"])["stdout"]
        executions = [
            execute(
                [
                    "/usr/local/bin/slither",
                    str(source),
                    "--json",
                    "-",
                    "--config-file",
                    "/opt/sentinel/slither.json",
                    "--solc",
                    "/usr/local/bin/solc",
                ]
            )
            for source in sorted(Path("/src").rglob("*.sol"))
        ]
    else:
        raise ValueError("Unsupported tool")
    print(json.dumps({"tool": tool, "version": str(version).strip(), "executions": executions}))


if __name__ == "__main__":
    main()
