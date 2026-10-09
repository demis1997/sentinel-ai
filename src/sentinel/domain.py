"""Evidence classifications deliberately separate from model confidence."""

from enum import StrEnum
from hashlib import sha256
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class EvidenceStrength(StrEnum):
    PLAUSIBLE = "plausible_unverified"
    STATIC = "statically_supported"
    REPRODUCED = "reproduced_under_tested_assumptions"
    INCONCLUSIVE = "inconclusive"


class Candidate(StrictModel):
    rule: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    path: str
    start: int = Field(ge=1)
    end: int = Field(ge=1)
    summary: str
    evidence: str
    strength: EvidenceStrength = EvidenceStrength.PLAUSIBLE

    @field_validator("strength")
    @classmethod
    def prevent_unsupported_reproduction(cls, value: EvidenceStrength) -> EvidenceStrength:
        if value == EvidenceStrength.REPRODUCED:
            raise ValueError(
                "Reproduction requires a verification evidence model; unavailable in v0.1"
            )
        return value

    def fingerprint(self, revision: str) -> str:
        # Exact source locations only; semantic cross-tool dedup is deliberately deferred.
        value = f"{revision}:{self.rule}:{self.path}:{self.start}:{self.end}"
        return sha256(value.encode()).hexdigest()


class AnalyzerResult(StrictModel):
    tool: str
    version: str
    status: Literal["completed", "unavailable", "failed"]
    findings: list[Candidate] = Field(default_factory=list)
    raw: str = ""
    error: str | None = None
    duration_ms: int = 0


class SourceFile(StrictModel):
    path: str
    sha256: str
    size: int


class Manifest(StrictModel):
    revision: str
    files: list[SourceFile]
    configurations: list[str]
    compiler_pragmas: list[str]
    origin: Literal["local_archive"] = "local_archive"
    # Local archives are content pinned, never misrepresented as Git commits.
    git_commit: str | None = None
