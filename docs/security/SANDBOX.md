# Source-only analyzer sandbox

The implemented Docker adapter is **disabled by default and has not been validated against a real container engine**. Its unit tests exercise policy and synthetic output. They are not evidence of isolation.

## Supported policy

The initial adapter requires rootless Linux Docker, cgroup v2, a confined default seccomp profile, and affirmative memory/swap/PID/CPU capability reporting. Rootful Docker Desktop does not meet this stricter initial policy. A reviewed image must provide `/usr/local/bin/python`, `/usr/local/bin/slither`, `/usr/local/bin/semgrep`, and a fixed `/usr/local/bin/solc` compatible with the source. No compiler is downloaded during a scan.

The wrapper Dockerfile requires an operator-supplied toolchain image. It has no default mutable base or automatic dependency downloads. Provide a reviewed registry digest as `TOOLCHAIN_IMAGE`, build from `sandbox/images`, then obtain the immutable local `sha256:…` image ID. Pin and lock the toolchain's transitive dependencies separately before treating the resulting image as reproducible. Image construction has not run in this environment.

The runner stages only `.sol` files beneath a private temporary parent. It mounts the readable child read-only; original repository scripts/configuration and host credentials are absent. Commands run with network disabled, UID/GID 65532, all capabilities dropped, no-new-privileges, a read-only root, two bounded writable tmpfs mounts, one CPU, 512 MiB memory with no additional swap, 64 PIDs, and a 256-file-descriptor limit. No host PID/IPC/network namespaces or Docker socket are mounted. Docker logging is disabled; bounded output is captured through the CLI instead. Images cannot be pulled automatically.

The outer Docker command has a 180-second wall budget and a 2 MiB output budget. Individual wrapper tool commands have a 90-second timeout. The host watchdog kills the Docker CLI and attempts force-removal of the named ephemeral container on completion or failure. If cleanup cannot be established, the worker fails and requires operator attention. Durable cleanup across a worker/host crash needs a reaper; this is not implemented.

Slither targets individual Solidity files with an explicit trusted config and fixed compiler, avoiding Foundry/Hardhat script discovery. Semgrep uses a bundled local rule and metrics/version checks are disabled. The initial Semgrep rule asks reviewers to investigate `tx.origin`; it is not a complete smart contract audit ruleset. Imports must already be present as source files, and compiler versions/remappings may make projects unsupported. Slither may report the same detector through multiple elements; location fingerprints preserve exact matches.

## Enable only after validation

Before setting `SENTINEL_ANALYZER_IMAGE=sha256:…` and `SENTINEL_SANDBOX_VALIDATED=1`, validate the image and engine using execution tests covering external network/metadata denial, read-only mounts, root filesystem writes, UID, capability and seccomp confinement, PID/memory/CPU/disk controls, output exhaustion, wall timeout, and cleanup. Run this on an isolated development machine with no application credentials. These tests and runtime evidence are pending in the checklist, so the supplied demo leaves execution disabled.

An environment flag is an operator attestation, not an isolation proof. The adapter still runs its capability preflight and command policy when enabled. There is no API endpoint or model-generated command that can enable it. Container isolation shares a kernel and is not a sufficient security boundary for a hostile multi-tenant hosted service; a VM or stronger sandbox remains an architectural requirement to evaluate.

References: [Docker run controls](https://docs.docker.com/engine/containers/run/), [rootless resource limitations](https://docs.docker.com/engine/security/rootless/tips/), [Slither usage](https://github.com/crytic/slither/wiki/Usage).
