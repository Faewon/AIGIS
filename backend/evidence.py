"""Typed provenance and assessment vocabulary shared by all agents."""
from enum import Enum
import hashlib
import os
from pathlib import Path
import time
import uuid

from pydantic import BaseModel, ConfigDict, Field


class AssessmentState(str, Enum):
    NOT_ASSESSED = "NOT_ASSESSED"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    NO_SIGNAL_OBSERVED = "NO_SIGNAL_OBSERVED"
    SIGNAL_DETECTED = "SIGNAL_DETECTED"
    EXPLOIT_REPRODUCED_IN_MOCK = "EXPLOIT_REPRODUCED_IN_MOCK"
    MITIGATION_VERIFIED_IN_MOCK = "MITIGATION_VERIFIED_IN_MOCK"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"


class DatasetIdentity(BaseModel):
    model_config = ConfigDict(frozen=True)
    dataset_id: str
    database_path: str
    dataset_revision: str


def dataset_identity(path: str) -> DatasetIdentity:
    """Fingerprint the file and WAL, including replacement at the same path.

    This is a conservative cache invalidator, not a cryptographic content hash.
    Any write can invalidate cached results, including auxiliary-table writes.
    """
    absolute = str(Path(path).resolve())
    signature = []
    for suffix in ("", "-wal"):
        try:
            stat = os.stat(absolute + suffix)
            signature.append((stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns))
        except OSError:
            signature.append(None)
    return DatasetIdentity(
        dataset_id=hashlib.sha256(os.path.normcase(absolute).encode()).hexdigest()[:24],
        database_path=absolute,
        dataset_revision=hashlib.sha256(repr(signature).encode()).hexdigest(),
    )


class AnalysisContext(BaseModel):
    model_config = ConfigDict(frozen=True)
    run_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    dataset_id: str
    dataset_revision: str
    database_path: str
    target_endpoint: str | None = None
    window_start_ms: int
    window_end_ms: int
    coverage_complete: bool = True
    source: str = "SQLITE_READ_SNAPSHOT"
    analyzed_count: int = 0


def analysis_context(path: str, window_seconds: int, endpoint: str | None = None,
                     now_ms: int | None = None, **fields) -> AnalysisContext:
    end = int(time.time() * 1000) if now_ms is None else now_ms
    return AnalysisContext(**dataset_identity(path).model_dump(), target_endpoint=endpoint,
                           window_start_ms=end - window_seconds * 1000,
                           window_end_ms=end, **fields)


class SimulationEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)
    run_id: str
    scenario: str
    workload_id: str
    phase: str
    seed: int
    controls: dict[str, bool]
    source: str = "IN_PROCESS_MOCK"


class ScenarioMeasurement(BaseModel):
    model_config = ConfigDict(extra="allow", allow_inf_nan=False)
    scenario: str
    status: str
    total_requests: int = Field(ge=1)
    successful_requests: int = Field(ge=0)
    blocked_requests: int = Field(ge=0)
    illegal_claims_count: int = Field(ge=0)
    total_stolen_amount: float = Field(ge=0)
    illegal_stolen_amount: float | None = Field(default=None, ge=0)
    evidence: SimulationEvidence | None = None


def pair_error(attack: dict, retest: dict) -> str | None:
    """Never score unrelated workloads as a before/after comparison."""
    if not attack or not retest:
        return "Attack and retest evidence are both required."
    if attack.get("scenario") != retest.get("scenario"):
        return "Attack and retest scenarios differ."
    if attack.get("total_requests") != retest.get("total_requests"):
        return "Attack and retest workloads differ."
    left, right = attack.get("evidence"), retest.get("evidence")
    if bool(left) != bool(right):
        return "Only one report has provenance."
    if left and any(left.get(key) != right.get(key) for key in ("run_id", "scenario", "workload_id", "seed")):
        return "Attack and retest provenance does not match."
    return None


def illegal_loss(report: dict) -> float:
    return float(report.get("illegal_stolen_amount", report.get("total_stolen_amount", 0)) or 0)
