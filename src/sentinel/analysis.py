"""Safe lexical baseline and parsers for real sandbox analyzer output."""

import json
import re
from pathlib import Path
from typing import Protocol

from sentinel.domain import AnalyzerResult, Candidate, EvidenceStrength, Manifest


class Analyzer(Protocol):
    tool: str

    def run(self, manifest: Manifest, snapshot: Path) -> AnalyzerResult: ...


def code_only(text: str) -> str:
    # Keep line numbers while removing comments and strings to reduce lexical noise.
    pattern = r"""//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'"""
    return re.sub(pattern, lambda m: "".join("\n" if c == "\n" else " " for c in m.group()), text)


class LexicalAnalyzer:
    """Review candidates, not compiler-aware vulnerabilities or Slither substitutes."""

    tool = "sentinel-lexical"

    def run(self, manifest: Manifest, snapshot: Path) -> AnalyzerResult:
        findings: list[Candidate] = []
        rules = [
            ("tx-origin", r"\btx\s*\.\s*origin\b", "Review origin-based authorization"),
            ("delegatecall", r"\.\s*delegatecall\b", "Review delegatecall trust boundary"),
            ("low-level-call", r"\.\s*call\s*(?:\{|\()", "Review external call and state ordering"),
        ]
        for source in manifest.files:
            if not source.path.endswith(".sol"):
                continue
            original = (snapshot / source.path).read_text()
            clean = code_only(original)
            for rule, pattern, summary in rules:
                for match in re.finditer(pattern, clean):
                    line = clean.count("\n", 0, match.start()) + 1
                    findings.append(
                        Candidate(
                            rule=rule,
                            severity="info",
                            confidence="low",
                            path=source.path,
                            start=line,
                            end=line,
                            summary=summary,
                            evidence=original.splitlines()[line - 1][:1000],
                        )
                    )
        return AnalyzerResult(
            tool="sentinel-lexical",
            version="0.1.0",
            status="completed",
            findings=findings,
            raw=json.dumps([f.model_dump(mode="json") for f in findings]),
        )


def validated_location(path: str, start: int, end: int, manifest: Manifest) -> str:
    path = path.removeprefix("/src/")
    if path not in {f.path for f in manifest.files} or start < 1 or end < start:
        raise ValueError("Analyzer returned a location outside the source manifest")
    return path


def parse_semgrep(raw: str, manifest: Manifest, version: str) -> AnalyzerResult:
    data = json.loads(raw)
    if data.get("errors"):
        return AnalyzerResult(
            tool="semgrep",
            version=version,
            status="failed",
            raw=raw,
            error="Semgrep reported errors",
        )
    findings = []
    for result in data["results"]:
        start, end = result["start"]["line"], result["end"]["line"]
        extra = result["extra"]
        findings.append(
            Candidate(
                rule=result["check_id"],
                path=validated_location(result["path"], start, end, manifest),
                start=start,
                end=end,
                severity=(
                    "high"
                    if extra["severity"] == "ERROR"
                    else "medium"
                    if extra["severity"] == "WARNING"
                    else "info"
                ),
                confidence="medium",
                summary=extra["message"],
                evidence=json.dumps(result),
                strength=EvidenceStrength.STATIC,
            )
        )
    return AnalyzerResult(
        tool="semgrep", version=version, status="completed", raw=raw, findings=findings
    )


def parse_slither(raw: str, manifest: Manifest, version: str) -> AnalyzerResult:
    data = json.loads(raw)
    if not data["success"]:
        return AnalyzerResult(
            tool="slither",
            version=version,
            status="failed",
            raw=raw,
            error=str(data.get("error", "Slither failed")),
        )
    findings = []
    for detector in data["results"].get("detectors", []):
        for element in detector["elements"]:
            mapping = element["source_mapping"]
            lines = mapping["lines"]
            if not lines:
                continue
            start, end = min(lines), max(lines)
            findings.append(
                Candidate(
                    rule=detector["check"],
                    path=validated_location(
                        mapping.get("filename_absolute", mapping["filename_relative"]),
                        start,
                        end,
                        manifest,
                    ),
                    start=start,
                    end=end,
                    severity=detector["impact"].lower()
                    if detector["impact"].lower() in {"low", "medium", "high"}
                    else "info",
                    confidence=detector["confidence"].lower()
                    if detector["confidence"].lower() in {"low", "medium", "high"}
                    else "low",
                    summary=detector["description"],
                    evidence=json.dumps(detector),
                    strength=EvidenceStrength.STATIC,
                )
            )
    return AnalyzerResult(
        tool="slither", version=version, status="completed", raw=raw, findings=findings
    )
