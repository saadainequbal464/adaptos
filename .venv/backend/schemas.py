"""Agnos AI factory-visible data contracts.

Sealed test contents have no schema here by design. The factory only ever sees a
SealedSetCommitment (counts + hash) and a signed Verdict. Sealed cases are
generated, stored and graded inside the evaluation plane.
"""

import hashlib
import json
import math
from pathlib import PurePosixPath, PureWindowsPath
from typing import Annotated, Any, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

MIN_CASES_PER_CRITERION = 5
CONFIDENCE_LEVEL = 0.95
_Z = 1.959963984540054  # two-sided z for CONFIDENCE_LEVEL
_TOL = 1e-9

Identifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")]
ModelId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,99}$")]
Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
# Ed25519 signatures are stored as 64 raw bytes in lower-case hex (128 chars),
# matching Ed25519Signer.sign() -> .hex() and verify_signature() -> bytes.fromhex().
Ed25519Sig = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{128}$")]
Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]
Goal = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=4000)]

DataType = Literal["string", "number", "integer", "boolean", "object", "array", "file"]
CriterionMethod = Literal["exact_match", "schema_valid", "contains", "numeric_tolerance", "rubric"]
ArchitectureKind = Literal["prompt_only", "long_context", "retrieval", "tool_use"]
ReasoningEffort = Literal["minimal", "low", "medium", "high", "xhigh"]
CriterionStatus = Literal["met", "not_met", "undetermined"]
VerdictStatus = Literal["ready", "insufficient_evidence", "not_ready"]
FactoryStage = Literal[
    "intake",
    "spec_review",
    "eval_design",
    "building",
    "dev_testing",
    "repairing",
    "frozen",
    "evaluating",
    "verdicted",
    "verdict_issued",
    "delivered",
    "failed",
]

# Fields that must already exist before a stage may be entered.
_STAGE_REQUIRES: dict[str, tuple[str, ...]] = {
    "eval_design": ("approved_spec_hash",),
    "building": ("approved_spec_hash", "sealed"),
    "dev_testing": ("approved_spec_hash", "sealed", "candidate"),
    "repairing": ("approved_spec_hash", "sealed", "candidate"),
    "frozen": ("approved_spec_hash", "sealed", "frozen"),
    "evaluating": ("approved_spec_hash", "sealed", "frozen"),
    "verdicted": ("frozen", "verdict"),
    "verdict_issued": ("frozen", "verdict"),
    "delivered": ("frozen", "verdict"),
}


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def wilson_interval(n_passed: int, n_cases: int) -> tuple[float, float]:
    """Two-sided Wilson score interval at CONFIDENCE_LEVEL."""
    if n_cases <= 0:
        raise ValueError("n_cases must be positive")
    if n_passed < 0 or n_passed > n_cases:
        raise ValueError("n_passed must be between 0 and n_cases")
    p = n_passed / n_cases
    z2 = _Z * _Z
    denom = 1.0 + z2 / n_cases
    centre = (p + z2 / (2.0 * n_cases)) / denom
    half = _Z * math.sqrt(p * (1.0 - p) / n_cases + z2 / (4.0 * n_cases * n_cases)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def required_cases(threshold: float) -> int:
    """Smallest sealed-case count at which a perfect run can still reach 'met'.

    A perfect run has Wilson lower bound n / (n + z^2), so n >= z^2 * t / (1 - t).
    """
    return max(MIN_CASES_PER_CRITERION, math.ceil(_Z * _Z * threshold / (1.0 - threshold)))


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FrozenModel(StrictModel):
    model_config = ConfigDict(frozen=True)


# --------------------------------------------------------------------------- #
# Specification
# --------------------------------------------------------------------------- #


class FieldSpec(StrictModel):
    name: Identifier
    data_type: DataType
    description: Text
    required: bool = True


class AcceptanceCriterion(StrictModel):
    criterion_id: Identifier
    description: Text
    method: CriterionMethod
    # <= 0.95: the confidence-interval gate can never reach 'met' at 1.0.
    min_pass_rate: float = Field(gt=0.0, le=0.95)


class OpenQuestion(StrictModel):
    question_id: Identifier
    question: Text
    blocking: bool = True
    answer: Text | None = None


class SpecDraft(StrictModel):
    """Incomplete spec produced during intake. Downstream agents never receive this type."""

    goal: str = Field("", max_length=4000)
    inputs: list[FieldSpec] = Field(default_factory=list, max_length=50)
    outputs: list[FieldSpec] = Field(default_factory=list, max_length=50)
    constraints: list[Text] = Field(default_factory=list, max_length=50)
    acceptance_criteria: list[AcceptanceCriterion] = Field(default_factory=list, max_length=50)
    assumptions: list[Text] = Field(default_factory=list, max_length=50)
    open_questions: list[OpenQuestion] = Field(default_factory=list, max_length=50)

    def to_spec(self) -> "Spec":
        return Spec.model_validate(self.model_dump())


class Spec(StrictModel):
    goal: Goal
    inputs: list[FieldSpec] = Field(min_length=1, max_length=50)
    outputs: list[FieldSpec] = Field(min_length=1, max_length=50)
    constraints: list[Text] = Field(default_factory=list, max_length=50)
    acceptance_criteria: list[AcceptanceCriterion] = Field(min_length=1, max_length=50)
    assumptions: list[Text] = Field(default_factory=list, max_length=50)
    open_questions: list[OpenQuestion] = Field(default_factory=list, max_length=50)

    @model_validator(mode="after")
    def _check_consistency(self) -> "Spec":
        criterion_ids = [c.criterion_id for c in self.acceptance_criteria]
        if len(criterion_ids) != len(set(criterion_ids)):
            raise ValueError("duplicate criterion_id")
        for label, fields in (("input", self.inputs), ("output", self.outputs)):
            names = [f.name for f in fields]
            if len(names) != len(set(names)):
                raise ValueError(f"duplicate {label} name")
        question_ids = [q.question_id for q in self.open_questions]
        if len(question_ids) != len(set(question_ids)):
            raise ValueError("duplicate question_id")
        if any(q.blocking and not q.answer for q in self.open_questions):
            raise ValueError("unresolved blocking question")
        return self

    def content_hash(self) -> str:
        return sha256_hex(canonical_json(self.model_dump(mode="json")))


# --------------------------------------------------------------------------- #
# Development tests (builder-visible)
# --------------------------------------------------------------------------- #


class DevCase(FrozenModel):
    case_id: Identifier
    input_data: dict[str, Any]
    expected_output: dict[str, Any] | str
    criterion_ids: tuple[Identifier, ...] = Field(min_length=1)


class DevCaseResult(FrozenModel):
    case_id: Identifier
    passed: bool
    score: float = Field(0.0, ge=0.0, le=1.0)
    failure_note: str = Field("", max_length=1000)


class DevRun(FrozenModel):
    version_id: Identifier
    results: tuple[DevCaseResult, ...]

    @model_validator(mode="after")
    def _unique_cases(self) -> "DevRun":
        ids = [r.case_id for r in self.results]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate case_id in run")
        return self

    @property
    def pass_rate(self) -> float:
        if not self.results:
            return 0.0
        return sum(r.passed for r in self.results) / len(self.results)


# --------------------------------------------------------------------------- #
# Artifact identity and lifecycle
# --------------------------------------------------------------------------- #


class ArtifactFile(FrozenModel):
    path: str = Field(min_length=1, max_length=256)
    sha256: Sha256Hex
    size_bytes: int = Field(ge=0, le=10_000_000)

    @field_validator("path")
    @classmethod
    def _safe_relative_path(cls, value: str) -> str:
        posix = PurePosixPath(value)
        if (
            not posix.parts
            or posix.is_absolute()
            or ".." in posix.parts
            or "\\" in value
            or "\x00" in value
            or value != posix.as_posix()
        ):
            raise ValueError("path must be a normalized relative POSIX file path")
        windows = PureWindowsPath(value)
        if windows.is_absolute() or windows.drive or windows.root:
            raise ValueError("path must not be a Windows absolute or drive-qualified path")
        return value


class RuntimeLimits(FrozenModel):
    """Per-invocation sandbox limits. The sandbox has no network: model and tool
    calls go through the runtime's model port and tool broker, never directly."""

    wall_seconds: int = Field(30, ge=1, le=120)
    memory_mb: int = Field(512, ge=64, le=2048)


class ArtifactRef(FrozenModel):
    version_id: Identifier
    artifact_hash: Sha256Hex


class ArtifactContent(FrozenModel):
    """Everything that defines runtime behavior; all of it is covered by the artifact hash."""

    spec_hash: Sha256Hex
    architecture: ArchitectureKind
    runtime_model: ModelId
    reasoning_effort: ReasoningEffort | None = None
    entrypoint: str = Field(min_length=1, max_length=256)
    files: tuple[ArtifactFile, ...] = Field(min_length=1, max_length=200)
    allowed_tools: tuple[Identifier, ...] = ()
    limits: RuntimeLimits = Field(default_factory=RuntimeLimits)

    @model_validator(mode="after")
    def _check_content(self) -> "ArtifactContent":
        paths = [f.path for f in self.files]
        if len(paths) != len(set(paths)):
            raise ValueError("duplicate file path")
        if self.entrypoint not in paths:
            raise ValueError("entrypoint must be one of the artifact files")
        if self.allowed_tools and self.architecture != "tool_use":
            raise ValueError("allowed_tools requires the tool_use architecture")
        return self

    def content_hash(self) -> str:
        payload = self.model_dump(mode="json", include=set(ArtifactContent.model_fields))
        payload["files"] = sorted(payload["files"], key=lambda f: f["path"])
        payload["allowed_tools"] = sorted(payload["allowed_tools"])
        return sha256_hex(canonical_json(payload))


class BundleManifest(ArtifactContent):
    version_id: Identifier
    parent_version_id: Identifier | None = None
    artifact_hash: Sha256Hex
    created_at: AwareDatetime

    @model_validator(mode="after")
    def _verify_hash(self) -> "BundleManifest":
        if self.artifact_hash != self.content_hash():
            raise ValueError("artifact_hash does not match manifest content")
        return self

    @property
    def ref(self) -> ArtifactRef:
        return ArtifactRef(version_id=self.version_id, artifact_hash=self.artifact_hash)

    @classmethod
    def seal(
        cls,
        content: ArtifactContent,
        *,
        version_id: str,
        created_at: AwareDatetime,
        parent_version_id: str | None = None,
    ) -> "BundleManifest":
        return cls(
            **dict(content),
            version_id=version_id,
            parent_version_id=parent_version_id,
            artifact_hash=content.content_hash(),
            created_at=created_at,
        )


class RepairRecord(FrozenModel):
    attempt: int = Field(ge=1)
    parent_version_id: Identifier
    new_version_id: Identifier
    target_component: Text
    accepted: bool
    reason: str = Field("", max_length=500)


# --------------------------------------------------------------------------- #
# Evaluation-plane contracts (factory-visible side only)
# --------------------------------------------------------------------------- #


class SealedSetRequest(FrozenModel):
    """Factory -> evaluation plane. The evaluation plane generates and seals the cases
    itself from the spec; no sealed case ever passes through the factory."""

    spec: Spec
    cases_per_criterion: int = Field(100, ge=MIN_CASES_PER_CRITERION, le=200)

    @model_validator(mode="after")
    def _ready_must_be_reachable(self) -> "SealedSetRequest":
        for c in self.spec.acceptance_criteria:
            need = required_cases(c.min_pass_rate)
            if self.cases_per_criterion < need:
                raise ValueError(
                    f"{c.criterion_id}: needs >= {need} sealed cases for 'ready' to be reachable"
                )
        return self


class SealedSetCommitment(FrozenModel):
    """Proof that a sealed set exists. Contains no case ids, inputs, or expected outputs."""

    set_id: Identifier
    spec_hash: Sha256Hex
    case_count: int = Field(ge=1)
    criterion_case_counts: dict[Identifier, int]
    commitment_hash: Sha256Hex
    sealed_at: AwareDatetime

    @model_validator(mode="after")
    def _check_coverage(self) -> "SealedSetCommitment":
        if not self.criterion_case_counts:
            raise ValueError("no criterion coverage")
        if min(self.criterion_case_counts.values()) < MIN_CASES_PER_CRITERION:
            raise ValueError("criterion below minimum case count")
        return self


class EvaluationRequest(FrozenModel):
    """Light form: artifact ref + hashes. The protected evaluator also accepts the
    rich binding form (full BundleManifest / Spec / SealedSetCommitment) and re-verifies
    every hash chain in S1, so all fields are optional except the artifact reference."""
    artifact: ArtifactRef | BundleManifest
    spec_hash: Sha256Hex | None = None
    sealed_set_id: Identifier | None = None
    spec: Spec | None = None
    sealed: SealedSetCommitment | None = None


class CriterionResult(FrozenModel):
    """Aggregate result for one criterion. Statistics are re-derived from the counts
    on validation, so they cannot disagree with them."""

    criterion_id: Identifier
    threshold: float = Field(gt=0.0, le=0.95)
    n_cases: int = Field(ge=0)
    n_passed: int = Field(ge=0)
    status: CriterionStatus
    pass_rate: float | None = Field(None, ge=0.0, le=1.0)
    ci_low: float | None = Field(None, ge=0.0, le=1.0)
    ci_high: float | None = Field(None, ge=0.0, le=1.0)

    @classmethod
    def from_counts(
        cls, criterion_id: str, threshold: float, n_cases: int, n_passed: int
    ) -> "CriterionResult":
        if not 0 <= n_passed <= n_cases:
            raise ValueError("n_passed must be between 0 and n_cases")
        if n_cases < MIN_CASES_PER_CRITERION:
            return cls(
                criterion_id=criterion_id,
                threshold=threshold,
                n_cases=n_cases,
                n_passed=n_passed,
                status="undetermined",
            )
        low, high = wilson_interval(n_passed, n_cases)
        if low >= threshold:
            status: CriterionStatus = "met"
        elif high < threshold:
            status = "not_met"
        else:
            status = "undetermined"
        return cls(
            criterion_id=criterion_id,
            threshold=threshold,
            n_cases=n_cases,
            n_passed=n_passed,
            status=status,
            pass_rate=n_passed / n_cases,
            ci_low=low,
            ci_high=high,
        )

    @model_validator(mode="after")
    def _check_result(self) -> "CriterionResult":
        if self.n_passed > self.n_cases:
            raise ValueError("n_passed exceeds n_cases")
        stats = (self.pass_rate, self.ci_low, self.ci_high)
        if self.n_cases < MIN_CASES_PER_CRITERION:
            if self.status != "undetermined" or any(v is not None for v in stats):
                raise ValueError("small-sample results must be undetermined and unreported")
            return self
        if self.pass_rate is None or self.ci_low is None or self.ci_high is None:
            raise ValueError("pass_rate and interval are required")
        low, high = wilson_interval(self.n_passed, self.n_cases)
        if (
            abs(self.pass_rate - self.n_passed / self.n_cases) > _TOL
            or abs(self.ci_low - low) > _TOL
            or abs(self.ci_high - high) > _TOL
        ):
            raise ValueError("statistics do not match counts")
        if low >= self.threshold:
            expected = "met"
        elif high < self.threshold:
            expected = "not_met"
        else:
            expected = "undetermined"
        if self.status != expected:
            raise ValueError(f"status must be {expected}")
        return self


class Verdict(FrozenModel):
    """Issued and signed by the evaluation plane. The factory can verify, never forge:
    signatures are asymmetric (Ed25519), so the factory holds only the public key."""

    # Optional traceability id assigned by the evaluation plane when it issues the verdict.
    verdict_id: str | None = None
    status: VerdictStatus
    artifact: ArtifactRef
    spec_hash: Sha256Hex
    sealed_set_id: Identifier
    sealed_commitment_hash: Sha256Hex
    criteria: tuple[CriterionResult, ...] = Field(min_length=1)
    judge_model: ModelId | None = None
    evidence_hash: Sha256Hex  # hash of the evaluation plane's private per-case evidence
    signing_key_id: Identifier
    signature_alg: Literal["ed25519"] = "ed25519"
    issued_at: AwareDatetime
    signature: Ed25519Sig

    @model_validator(mode="after")
    def _check_verdict(self) -> "Verdict":
        ids = [c.criterion_id for c in self.criteria]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate criterion_id")
        statuses = {c.status for c in self.criteria}
        if "not_met" in statuses:
            expected = "not_ready"
        elif "undetermined" in statuses:
            expected = "insufficient_evidence"
        else:
            expected = "ready"
        if self.status != expected:
            raise ValueError(f"status must be {expected}")
        return self

    def signing_payload(self) -> bytes:
        return canonical_json(self.model_dump(mode="json", exclude={"signature"}))


class DeliveryPackage(FrozenModel):
    spec: Spec
    manifest: BundleManifest
    verdict: Verdict
    repair_log: tuple[RepairRecord, ...] = ()
    delivered_at: AwareDatetime

    @model_validator(mode="after")
    def _check_binding(self) -> "DeliveryPackage":
        spec_hash = self.spec.content_hash()
        if self.verdict.artifact != self.manifest.ref:
            raise ValueError("verdict does not match delivered artifact")
        if self.verdict.spec_hash != spec_hash or self.manifest.spec_hash != spec_hash:
            raise ValueError("spec hash mismatch")
        spec_criteria = {c.criterion_id: c for c in self.spec.acceptance_criteria}
        results = {c.criterion_id: c for c in self.verdict.criteria}
        if set(results) != set(spec_criteria):
            raise ValueError("verdict must cover exactly the spec's acceptance criteria")
        for cid, result in results.items():
            if abs(result.threshold - spec_criteria[cid].min_pass_rate) > _TOL:
                raise ValueError(f"{cid}: verdict threshold differs from spec")
        return self


# --------------------------------------------------------------------------- #
# Factory workflow state
# --------------------------------------------------------------------------- #


class ErrorRecord(FrozenModel):
    stage: FactoryStage
    code: Identifier
    message: str = Field("", max_length=500)


class FactoryState(StrictModel):
    """Serializable LangGraph state. Holds no sealed contents, case ids, secrets, or
    per-case hidden results."""

    model_config = ConfigDict(validate_assignment=True)

    stage: FactoryStage = "intake"
    user_goal: str = Field("", max_length=4000)

    draft_spec: SpecDraft = Field(default_factory=SpecDraft)
    spec: Spec | None = None
    approved_spec_hash: Sha256Hex | None = None

    dev_case_ids: list[Identifier] = Field(default_factory=list)
    sealed: SealedSetCommitment | None = None

    baseline: BundleManifest | None = None
    candidate: BundleManifest | None = None
    last_passing: BundleManifest | None = None

    dev_runs: list[DevRun] = Field(default_factory=list)
    repair_log: list[RepairRecord] = Field(default_factory=list)
    max_repair_attempts: int = Field(3, ge=0, le=10)

    frozen: ArtifactRef | None = None
    verdict: Verdict | None = None
    errors: list[ErrorRecord] = Field(default_factory=list)

    @property
    def repair_attempts(self) -> int:
        return len(self.repair_log)

    @property
    def repair_budget_left(self) -> int:
        return self.max_repair_attempts - len(self.repair_log)

    @model_validator(mode="after")
    def _check_integrity(self) -> "FactoryState":
        if self.approved_spec_hash is not None and self.spec is None:
            raise ValueError("approved_spec_hash requires a spec")
        if self.spec is not None:
            spec_hash = self.spec.content_hash()
            if self.approved_spec_hash is not None and self.approved_spec_hash != spec_hash:
                raise ValueError("spec changed after approval")
            if self.sealed is not None:
                if self.sealed.spec_hash != spec_hash:
                    raise ValueError("sealed set does not match spec")
                criteria = {c.criterion_id: c for c in self.spec.acceptance_criteria}
                counts = self.sealed.criterion_case_counts
                if set(counts) != set(criteria):
                    raise ValueError("sealed set must cover exactly the spec's criteria")
                for cid, n in counts.items():
                    if n < required_cases(criteria[cid].min_pass_rate):
                        raise ValueError(f"{cid}: too few sealed cases for 'ready' to be reachable")
        if len(self.repair_log) > self.max_repair_attempts:
            raise ValueError("repair budget exceeded")
        if self.frozen is not None:
            known = {
                m.artifact_hash
                for m in (self.baseline, self.candidate, self.last_passing)
                if m is not None
            }
            if self.frozen.artifact_hash not in known:
                raise ValueError("frozen artifact is not a known version")
        if self.verdict is not None and (self.frozen is None or self.verdict.artifact != self.frozen):
            raise ValueError("verdict does not match frozen artifact")
        missing = [n for n in _STAGE_REQUIRES.get(self.stage, ()) if getattr(self, n) is None]
        if missing:
            raise ValueError(f"stage '{self.stage}' requires: {', '.join(missing)}")
        return self