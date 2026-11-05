"""backend/eval_plane/evaluator.py — Protected Evaluation Plane Coordinator & Grader.

Implements Components C1–C11 and Data Flow Steps S1–S12:
- BootGuard: Enforces AGNOS_PROCESS_ROLE=eval, rejects factory credentials in env, and verifies signing key.
- C1 SubmissionVerifier: Validates EvaluationJob envelope and S1 hash-binding chain + required_cases coverage.
- C2 SealedSetReader: Reads sealed held-out cases via VaultReaderPort, verifies full-case cryptographic hashes
  and commitment hash, and validates normalized case contracts.
- C3 ArtifactLoader: Verifies manifest & file bytes in-memory and runs AppRuntime.verify_bundle_integrity
  without touching factory storage.
- C4 EnvironmentFactory: Creates per-evaluation isolated scratch environment with per-attempt isolated
  fenced StorageService instances, scoped SandboxVerifier, and deadline-enforced MeteredEvalModelPort.
- C5 CaseExecutor: Establishes a single absolute per-case deadline across all retries, passes remaining
  timeout budgets to model calls, fences timed-out attempts from storage/API access, and classifies
  ok / artifact_error / infra_error.
- C6 CaseGrader & C6b JudgeAdapter: Stricter per-method deterministic grading on explicit target_fields only,
  plus blind pointwise JudgeAdapter verifying distinct judge model identity and binary rubric dimensions.
- C7 Aggregator: Tallies per-criterion counts and blocks partial verdicts when ungraded cases remain.
- C8 VerdictBuilderAndSigner: Builds CriterionResult objects, assembles Verdict, signs with Ed25519 at Step S11
  only, and self-verifies signature.
- C9 EvidenceRecorder: Writes private per-case evidence to eval DB and returns canonical evidence_hash.
- C10 EvaluationLedger: Durable state machine, atomic per-set budget reservation across concurrent runs,
  and cryptographically validated per-case crash recovery.
- C11 RedactionLayer: Strips all case inputs, expected values, and outputs from logs, errors, and abort payloads.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import copy
import inspect
import json
import math
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Final, Literal, Mapping, Protocol, Sequence

# Resolve the backend/ root that contains schemas.py, whether this file is run
# from .venv/eval_plane/, backend/eval_plane/, or imported as eval_plane.evaluator.
_CURRENT_DIR = Path(__file__).resolve().parent
_PARENT_DIR = _CURRENT_DIR.parent
_GRANDPARENT_DIR = _PARENT_DIR.parent
for _cand_dir in (
    _CURRENT_DIR,
    _PARENT_DIR / "backend",
    _PARENT_DIR,
    _GRANDPARENT_DIR / "backend",
    _GRANDPARENT_DIR,
):
    if (_cand_dir / "schemas.py").is_file() and str(_cand_dir) not in sys.path:
        sys.path.insert(0, str(_cand_dir))
        break

from pydantic import BaseModel, ConfigDict, Field, model_validator

from schemas import (
    AcceptanceCriterion,
    ArtifactContent,
    ArtifactFile,
    ArtifactRef,
    BundleManifest,
    CriterionMethod,
    CriterionResult,
    EvaluationRequest,
    FieldSpec,
    Identifier,
    ModelId,
    RuntimeLimits,
    SealedSetCommitment,
    Sha256Hex,
    Spec,
    Verdict,
    canonical_json,
    required_cases,
    sha256_hex,
)
from storage import StorageConfig, StorageError, StorageService
from sandbox import (
    SandboxConfig,
    SandboxVerifier,
    _simulated_docker_runner_for_tests,
)
from runtime import (
    AppRuntime,
    PlanStep,
    RuntimeExecutionError,
    RuntimeModelPort,
    SourceAssetInput,
)


# =========================================================================== #
# 1. CONSTANTS, ABORT CODES, LEDGER STATES & C11 REDACTION LAYER
# =========================================================================== #

GRADER_VERSION: Final[str] = "eval_grader/1.1"
FORBIDDEN_FACTORY_ENV_VARS: Final[frozenset[str]] = frozenset(
    {
        "FACTORY_PRIVATE_KEY",
        "BUILDER_API_KEY",
        "REPAIR_API_KEY",
        "INTAKE_API_KEY",
        "AGNOS_FACTORY_DB_URL",
        "FACTORY_SECRET_KEY",
    }
)


class AbortCode(str, Enum):
    BINDING_FAILED = "binding_failed"
    SEALED_SET_INVALID = "sealed_set_invalid"
    SEALED_SET_INSUFFICIENT = "sealed_set_insufficient"
    SEALED_SET_EXHAUSTED = "sealed_set_exhausted"
    ARTIFACT_INTEGRITY_FAILED = "artifact_integrity_failed"
    SANDBOX_UNAVAILABLE = "sandbox_unavailable"
    EVALUATION_INCOMPLETE = "evaluation_incomplete"
    EVALUATION_IN_PROGRESS = "evaluation_in_progress"
    EVIDENCE_STORE_UNAVAILABLE = "evidence_store_unavailable"
    SIGNING_UNAVAILABLE = "signing_unavailable"
    BUDGET_EXCEEDED = "budget_exceeded"
    BOOT_GUARD_FAILED = "boot_guard_failed"


class LedgerState(str, Enum):
    RECEIVED = "received"
    BOUND = "bound"
    EXECUTING = "executing"
    GRADED = "graded"
    SIGNED = "signed"
    STORED = "stored"
    RESUMABLE = "resumable"
    ABORTED = "aborted"


class EvaluationAbortError(RuntimeError):
    """Typed abort carrying ONLY an AbortCode and a redacted audit code (never case content)."""

    def __init__(self, code: AbortCode, *, audit_detail: str = "") -> None:
        self.code = code
        self.audit_detail = RedactionLayer.sanitize_code_only(
            audit_detail or code.value
        )
        super().__init__(f"eval_abort:{self.code.value}")


class RedactionLayer:
    """C11 — Guarantees that only safe error/audit codes appear in logs, errors, and responses."""

    _SAFE_CODE_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9_.:/\-]")

    @classmethod
    def sanitize_code_only(cls, token: str, max_len: int = 80) -> str:
        cleaned = cls._SAFE_CODE_RE.sub("_", str(token or "").strip())
        return cleaned[:max_len] or "redacted_error"


def _canonical_bytes(data: Any) -> bytes:
    res = canonical_json(data)
    return res if isinstance(res, bytes) else str(res).encode("utf-8")


def _strict_typed_equal(actual: Any, expected: Any) -> bool:
    """Strict typed equality with zero bool/int confusion and zero substring fallback."""
    if isinstance(expected, bool) or isinstance(actual, bool):
        return (
            isinstance(actual, bool)
            and isinstance(expected, bool)
            and (actual is expected)
        )
    if isinstance(expected, int) and isinstance(actual, int):
        return actual == expected
    if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
        return float(actual) == float(expected)
    if isinstance(expected, str):
        return isinstance(actual, str) and actual == expected
    if isinstance(expected, Mapping):
        if not isinstance(actual, Mapping) or set(actual.keys()) != set(
            expected.keys()
        ):
            return False
        return all(_strict_typed_equal(actual[k], expected[k]) for k in expected)
    if isinstance(expected, (list, tuple)):
        if not isinstance(actual, (list, tuple)) or len(actual) != len(expected):
            return False
        return all(
            _strict_typed_equal(a_elem, e_elem)
            for a_elem, e_elem in zip(actual, expected)
        )
    return bool(actual == expected)


def _spec_outputs_to_json_schema(outputs: Sequence[FieldSpec]) -> dict[str, Any]:
    props: dict[str, Any] = {}
    req: list[str] = []
    for f in outputs:
        props[f.name] = {
            "type": "string" if f.data_type == "file" else f.data_type,
            "description": f.description,
        }
        if f.required:
            req.append(f.name)
    return {"type": "object", "properties": props, "required": req}


def compute_sealed_case_hash(
    *,
    case_id: str,
    criterion_id: str,
    method: str,
    input_data: Mapping[str, Any],
    target_fields: Sequence[str],
    expected_output: Mapping[str, Any],
    numeric_tolerance: float = 1e-2,
    rubric_dimensions: Sequence[Mapping[str, Any]] = (),
) -> str:
    """Cryptographically binds the complete normalized sealed case."""
    payload = {
        "case_id": str(case_id),
        "criterion_id": str(criterion_id),
        "method": str(method),
        "input_data": dict(input_data),
        "target_fields": list(target_fields),
        "expected_output": dict(expected_output),
        "numeric_tolerance": round(float(numeric_tolerance), 9),
        "rubric_dimensions": [dict(d) for d in rubric_dimensions],
    }
    return sha256_hex(_canonical_bytes(payload))


# =========================================================================== #
# 2. DATA CONTRACTS & PORTS (Section 4)
# =========================================================================== #


class StrictEvalModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FrozenEvalModel(StrictEvalModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SealedEvaluationCase(FrozenEvalModel):
    """Normalized held-out case stored in the vault.

    Cryptographically binds case_id, criterion_id, method, input_data, target_fields,
    expected_output, numeric_tolerance, and rubric_dimensions via `input_signature_hash`.
    """

    case_id: Identifier
    criterion_id: Identifier
    method: CriterionMethod
    input_data: dict[str, Any]
    target_fields: tuple[Identifier, ...] = Field(min_length=1)
    expected_output: dict[str, Any] = Field(default_factory=dict)
    numeric_tolerance: float = Field(default=1e-2, ge=0.0)
    rubric_dimensions: tuple[dict[str, Any], ...] = ()
    input_signature_hash: Sha256Hex

    @model_validator(mode="before")
    @classmethod
    def _populate_case_hash_if_omitted(cls, data: Any) -> Any:
        if isinstance(data, Mapping) and not data.get("input_signature_hash"):
            d = dict(data)
            d["input_signature_hash"] = compute_sealed_case_hash(
                case_id=str(d.get("case_id", "")),
                criterion_id=str(d.get("criterion_id", "")),
                method=str(d.get("method", "")),
                input_data=d.get("input_data") or {},
                target_fields=d.get("target_fields") or (),
                expected_output=d.get("expected_output") or {},
                numeric_tolerance=float(d.get("numeric_tolerance", 1e-2)),
                rubric_dimensions=d.get("rubric_dimensions") or (),
            )
            return d
        return data

    def compute_case_hash(self) -> str:
        return compute_sealed_case_hash(
            case_id=self.case_id,
            criterion_id=self.criterion_id,
            method=self.method,
            input_data=self.input_data,
            target_fields=self.target_fields,
            expected_output=self.expected_output,
            numeric_tolerance=self.numeric_tolerance,
            rubric_dimensions=self.rubric_dimensions,
        )

    @model_validator(mode="after")
    def _check_seal_time_invariants(self) -> "SealedEvaluationCase":
        if self.method in ("exact_match", "contains", "numeric_tolerance"):
            for tf in self.target_fields:
                if tf not in self.expected_output:
                    raise ValueError(
                        f"Case '{self.case_id}' ({self.method}) missing target_field '{tf}' in expected_output."
                    )
        if self.method == "numeric_tolerance":
            for tf in self.target_fields:
                val = self.expected_output.get(tf)
                if not isinstance(val, (int, float)) or isinstance(val, bool):
                    raise ValueError(
                        f"Seal-time error on case '{self.case_id}': numeric_tolerance expected value "
                        f"for field '{tf}' must be int or float, got {type(val).__name__}."
                    )
        if self.method == "rubric":
            if not self.rubric_dimensions:
                raise ValueError(
                    f"Seal-time error on case '{self.case_id}': rubric method requires non-empty rubric_dimensions."
                )
            for dim in self.rubric_dimensions:
                if not isinstance(dim, Mapping) or not str(
                    dim.get("id") or dim.get("dimension_id") or ""
                ).strip():
                    raise ValueError(
                        f"Seal-time error on case '{self.case_id}': every rubric dimension must declare an 'id'."
                    )
        expected_hash = self.compute_case_hash()
        if self.input_signature_hash != expected_hash:
            raise ValueError(
                f"Case '{self.case_id}' input_signature_hash ({self.input_signature_hash}) "
                f"does not match complete normalized case hash ({expected_hash})."
            )
        return self


class EvaluationJob(FrozenEvalModel):
    """Inbound job envelope from service.py."""

    request_id: Identifier
    request: EvaluationRequest
    spec: Spec
    manifest: BundleManifest
    files_data: dict[str, bytes]
    assets: tuple[SourceAssetInput, ...] = ()


class EvaluationOutcome(FrozenEvalModel):
    """Outbound result from EvaluatorCoordinator: either a signed Verdict or a typed abort."""

    status: Literal["verdict_issued", "aborted"]
    verdict: Verdict | None = None
    abort_code: AbortCode | None = None
    audit_code: str = ""


class JudgeVerdict(FrozenEvalModel):
    """Pointwise binary rubric judgment returned by JudgePort."""

    passed: bool
    dimension_scores: dict[str, int] = Field(default_factory=dict)
    judge_model: ModelId


class VaultReaderPort(Protocol):
    def open_sealed_set(
        self, set_id: str, *, caller_role: str = "eval"
    ) -> tuple[SealedSetCommitment, tuple[SealedEvaluationCase, ...]]: ...


class JudgePort(Protocol):
    @property
    def judge_model_id(self) -> ModelId: ...

    def evaluate_rubric(
        self,
        *,
        criterion_description: str,
        dimensions: Sequence[Mapping[str, Any]],
        input_data: Mapping[str, Any],
        output_data: Mapping[str, Any],
    ) -> JudgeVerdict: ...


class SignerPort(Protocol):
    @property
    def key_id(self) -> str: ...

    @property
    def public_key_bytes(self) -> bytes: ...

    def sign(self, payload: bytes) -> str: ...


class ClockPort(Protocol):
    def now_utc(self) -> datetime: ...


class SystemUTCClock:
    def now_utc(self) -> datetime:
        return datetime.now(timezone.utc)


@dataclass(frozen=True)
class EvaluatorConfig:
    eval_db_path: Path
    vault_db_path: Path
    require_eval_role_env: bool = True
    max_output_bytes: int = 65_536
    max_infra_retries: int = 2
    infra_retry_delay_seconds: float = 0.02
    max_eval_wall_seconds: float = 120.0
    max_eval_cost_usd: float = 1.00
    max_evaluations_per_set: int = 1
    allow_resumable_incomplete: bool = False
    allow_subprocess_sandbox_fallback: bool = False


# =========================================================================== #
# 3. ED25519 SIGNER & BOOT GUARD (Section 2 & 7)
# =========================================================================== #


class Ed25519Signer:
    """Holds the Ed25519 private signing key inside the protected evaluation plane."""

    def __init__(self, private_seed_bytes: bytes) -> None:
        if not isinstance(private_seed_bytes, bytes) or len(private_seed_bytes) != 32:
            raise EvaluationAbortError(
                AbortCode.SIGNING_UNAVAILABLE, audit_detail="invalid_seed_length"
            )
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )

            self._priv = Ed25519PrivateKey.from_private_bytes(private_seed_bytes)
            pub = self._priv.public_key()
            self.public_key_bytes: bytes = pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            pub_sha = sha256_hex(self.public_key_bytes)
            self.key_id: str = f"ed25519-{pub_sha[:16]}"
        except Exception as exc:
            raise EvaluationAbortError(
                AbortCode.SIGNING_UNAVAILABLE,
                audit_detail=type(exc).__name__,
            ) from exc

    def sign(self, payload: bytes) -> str:
        try:
            return self._priv.sign(payload).hex()
        except Exception as exc:
            raise EvaluationAbortError(
                AbortCode.SIGNING_UNAVAILABLE,
                audit_detail=type(exc).__name__,
            ) from exc

    @staticmethod
    def verify_signature(
        public_key_bytes: bytes, payload: bytes, signature_hex: str
    ) -> bool:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            sig_bytes = bytes.fromhex(signature_hex)
            if len(sig_bytes) != 64 or len(public_key_bytes) != 32:
                return False
            pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            pub.verify(sig_bytes, payload)
            return True
        except Exception:
            return False


class BootGuard:
    """Section 2 Boot Guard: verifies process role, absence of factory credentials, and signing key."""

    @staticmethod
    def verify_startup(
        config: EvaluatorConfig,
        signer: SignerPort | None,
        *,
        env: Mapping[str, str] | None = None,
    ) -> None:
        active_env = env if env is not None else os.environ
        if config.require_eval_role_env:
            role_val = active_env.get("AGNOS_PROCESS_ROLE", "")
            if role_val != "eval":
                raise EvaluationAbortError(
                    AbortCode.BOOT_GUARD_FAILED,
                    audit_detail="missing_eval_process_role",
                )

        leaked_factory_vars = [
            k for k in FORBIDDEN_FACTORY_ENV_VARS if active_env.get(k)
        ]
        if leaked_factory_vars:
            raise EvaluationAbortError(
                AbortCode.BOOT_GUARD_FAILED,
                audit_detail="factory_credentials_present_in_eval_env",
            )

        if signer is None:
            raise EvaluationAbortError(
                AbortCode.SIGNING_UNAVAILABLE,
                audit_detail="signer_not_configured",
            )
        try:
            probe_sig = signer.sign(b"adaptos_eval_boot_probe")
            if not Ed25519Signer.verify_signature(
                signer.public_key_bytes, b"adaptos_eval_boot_probe", probe_sig
            ):
                raise ValueError("probe_verify_failed")
        except EvaluationAbortError:
            raise
        except Exception as exc:
            raise EvaluationAbortError(
                AbortCode.SIGNING_UNAVAILABLE,
                audit_detail=type(exc).__name__,
            ) from exc


# =========================================================================== #
# 4. C1 SUBMISSION VERIFIER, C2 SEALED SET READER & C3 ARTIFACT LOADER
# =========================================================================== #


class SubmissionVerifier:
    """C1 — Validates the job envelope and checks the S1 hash-binding chain & coverage floor."""

    @staticmethod
    def verify_s1_binding(job: EvaluationJob) -> None:
        req = job.request
        spec = job.spec
        manifest = job.manifest
        commitment = req.sealed

        try:
            computed_manifest_hash = manifest.content_hash()
        except Exception as exc:
            raise EvaluationAbortError(
                AbortCode.BINDING_FAILED, audit_detail=type(exc).__name__
            ) from exc

        req_art_hash = (
            req.artifact.artifact_hash
            if hasattr(req.artifact, "artifact_hash")
            else req.artifact.ref.artifact_hash
        )
        req_ver_id = (
            req.artifact.version_id
            if hasattr(req.artifact, "version_id")
            else req.artifact.ref.version_id
        )
        if (
            computed_manifest_hash != manifest.artifact_hash
            or manifest.artifact_hash != req_art_hash
            or manifest.version_id != req_ver_id
        ):
            raise EvaluationAbortError(
                AbortCode.BINDING_FAILED, audit_detail="artifact_hash_mismatch"
            )

        computed_spec_hash = spec.content_hash()
        req_spec_hash = (
            req.spec.content_hash()
            if hasattr(req, "spec") and req.spec is not None
            else getattr(req, "spec_hash", computed_spec_hash)
        )
        if (
            computed_spec_hash != req_spec_hash
            or computed_spec_hash != manifest.spec_hash
            or computed_spec_hash != commitment.spec_hash
        ):
            raise EvaluationAbortError(
                AbortCode.BINDING_FAILED, audit_detail="spec_hash_mismatch"
            )

        spec_crit_ids = {c.criterion_id for c in spec.acceptance_criteria}
        comm_crit_ids = set(commitment.criterion_case_counts.keys())
        if spec_crit_ids != comm_crit_ids:
            raise EvaluationAbortError(
                AbortCode.BINDING_FAILED, audit_detail="criterion_keys_mismatch"
            )

        for crit in spec.acceptance_criteria:
            req_count = required_cases(crit.min_pass_rate)
            actual_count = commitment.criterion_case_counts.get(
                crit.criterion_id, 0
            )
            if actual_count < req_count:
                raise EvaluationAbortError(
                    AbortCode.SEALED_SET_INSUFFICIENT,
                    audit_detail=f"insufficient_cases_for_{crit.criterion_id}",
                )


class SealedSetReader:
    """C2 — Opens sealed set via VaultReaderPort, verifies full-case hashes, commitment hash, and coverage."""

    def __init__(self, vault_port: VaultReaderPort) -> None:
        self.vault_port = vault_port

    def read_and_verify(
        self,
        *,
        expected_commitment: SealedSetCommitment,
        spec: Spec,
    ) -> tuple[SealedEvaluationCase, ...]:
        try:
            vault_commitment, cases = self.vault_port.open_sealed_set(
                expected_commitment.set_id, caller_role="eval"
            )
        except EvaluationAbortError:
            raise
        except Exception as exc:
            raise EvaluationAbortError(
                AbortCode.SEALED_SET_INVALID, audit_detail=type(exc).__name__
            ) from exc

        if (
            vault_commitment.set_id != expected_commitment.set_id
            or vault_commitment.spec_hash != spec.content_hash()
            or vault_commitment.commitment_hash != expected_commitment.commitment_hash
        ):
            raise EvaluationAbortError(
                AbortCode.SEALED_SET_INVALID,
                audit_detail="vault_commitment_mismatch",
            )

        actual_counts: dict[str, int] = {
            c.criterion_id: 0 for c in spec.acceptance_criteria
        }
        seen_case_ids: set[str] = set()
        crit_by_id = {c.criterion_id: c for c in spec.acceptance_criteria}
        declared_outputs = {f.name for f in spec.outputs}
        recomputed_case_hashes: list[str] = []

        for tc in cases:
            if not isinstance(tc, SealedEvaluationCase):
                raise EvaluationAbortError(
                    AbortCode.SEALED_SET_INVALID, audit_detail="invalid_case_object"
                )
            if tc.case_id in seen_case_ids:
                raise EvaluationAbortError(
                    AbortCode.SEALED_SET_INVALID, audit_detail="duplicate_case_id"
                )
            seen_case_ids.add(tc.case_id)
            if tc.criterion_id not in crit_by_id:
                raise EvaluationAbortError(
                    AbortCode.SEALED_SET_INVALID, audit_detail="unknown_criterion_id"
                )
            if tc.method != crit_by_id[tc.criterion_id].method:
                raise EvaluationAbortError(
                    AbortCode.SEALED_SET_INVALID,
                    audit_detail="criterion_method_mismatch",
                )
            if any(tf not in declared_outputs for tf in tc.target_fields):
                raise EvaluationAbortError(
                    AbortCode.SEALED_SET_INVALID,
                    audit_detail="undeclared_target_field",
                )

            try:
                _ = tc._check_seal_time_invariants()
                expected_full_hash = tc.compute_case_hash()
            except Exception as exc:
                raise EvaluationAbortError(
                    AbortCode.SEALED_SET_INVALID,
                    audit_detail=f"case_invariant_failed:{type(exc).__name__}",
                ) from exc

            if tc.input_signature_hash != expected_full_hash:
                raise EvaluationAbortError(
                    AbortCode.SEALED_SET_INVALID,
                    audit_detail="case_signature_hash_tampered",
                )
            recomputed_case_hashes.append(expected_full_hash)
            actual_counts[tc.criterion_id] += 1

        if (
            len(cases) != expected_commitment.case_count
            or actual_counts != dict(expected_commitment.criterion_case_counts)
        ):
            raise EvaluationAbortError(
                AbortCode.SEALED_SET_INVALID, audit_detail="case_count_mismatch"
            )

        recomputed_commitment_hash = sha256_hex(
            _canonical_bytes(
                {
                    "set_id": expected_commitment.set_id,
                    "spec_hash": spec.content_hash(),
                    "counts": actual_counts,
                    "case_hashes": recomputed_case_hashes,
                }
            )
        )
        if recomputed_commitment_hash != expected_commitment.commitment_hash:
            raise EvaluationAbortError(
                AbortCode.SEALED_SET_INVALID,
                audit_detail="commitment_hash_verification_failed",
            )

        for crit in spec.acceptance_criteria:
            if actual_counts[crit.criterion_id] < required_cases(crit.min_pass_rate):
                raise EvaluationAbortError(
                    AbortCode.SEALED_SET_INSUFFICIENT,
                    audit_detail=f"coverage_below_required_{crit.criterion_id}",
                )

        return cases


class ArtifactLoader:
    """C3 — Verifies manifest and file bytes in memory without touching factory storage."""

    @staticmethod
    def verify_bundle(
        manifest: BundleManifest, files_data: Mapping[str, bytes]
    ) -> None:
        try:
            AppRuntime.verify_bundle_integrity(manifest, files_data)
        except Exception as exc:
            raise EvaluationAbortError(
                AbortCode.ARTIFACT_INTEGRITY_FAILED,
                audit_detail=type(exc).__name__,
            ) from exc


# =========================================================================== #
# 5. C4 ENVIRONMENT FACTORY, ATTEMPT FENCING & TIMEOUT-PROPAGATING MODEL PORT
# =========================================================================== #


class InfrastructureModelError(RuntimeError):
    """Raised by the runtime model port on provider timeout, rate limit, or 5xx outage."""


class CaseDeadlineExceededError(RuntimeExecutionError):
    """Raised when a per-case execution deadline expires or a fenced attempt is revoked."""


class AttemptExecutionFence:
    """Thread-safe execution fence binding one attempt to a single absolute case deadline.

    Once the deadline expires or `revoke()` is called when the caller returns, any late-running
    background thread attempting to access storage or make model calls is immediately blocked.
    """

    def __init__(self, deadline_monotonic: float) -> None:
        self.deadline_monotonic = float(deadline_monotonic)
        self._lock = threading.Lock()
        self._revoked = False

    def revoke(self) -> None:
        with self._lock:
            self._revoked = True

    def remaining_seconds(self) -> float:
        with self._lock:
            if self._revoked:
                raise CaseDeadlineExceededError(
                    "case_wall_timeout_exceeded:attempt_fence_revoked"
                )
        rem = self.deadline_monotonic - time.monotonic()
        if rem <= 0:
            self.revoke()
            raise CaseDeadlineExceededError(
                "case_wall_timeout_exceeded:deadline_expired"
            )
        return rem

    def check_active(self) -> float:
        return self.remaining_seconds()


class _FencedAttemptStorage:
    """Wraps a per-attempt StorageService and blocks all operations once the attempt fence expires/revokes."""

    def __init__(
        self, inner_storage: StorageService, fence: AttemptExecutionFence
    ) -> None:
        self._inner = inner_storage
        self._fence = fence

    def provision_app_storage(self, *args: Any, **kwargs: Any) -> Any:
        self._fence.check_active()
        return self._inner.provision_app_storage(*args, **kwargs)

    def add_fts5_document(self, *args: Any, **kwargs: Any) -> Any:
        self._fence.check_active()
        return self._inner.add_fts5_document(*args, **kwargs)

    def search_fts5(self, *args: Any, **kwargs: Any) -> Any:
        self._fence.check_active()
        return self._inner.search_fts5(*args, **kwargs)

    def put_blob(self, *args: Any, **kwargs: Any) -> Any:
        self._fence.check_active()
        return self._inner.put_blob(*args, **kwargs)

    def get_blob(self, *args: Any, **kwargs: Any) -> Any:
        self._fence.check_active()
        return self._inner.get_blob(*args, **kwargs)

    def verify_blob(self, *args: Any, **kwargs: Any) -> Any:
        self._fence.check_active()
        return self._inner.verify_blob(*args, **kwargs)

    def get_factory_db(self, *args: Any, **kwargs: Any) -> Any:
        self._fence.check_active()
        return self._inner.get_factory_db(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        self._fence.check_active()
        return getattr(self._inner, name)


class MeteredEvalModelPort:
    """Wraps RuntimeModelPort to enforce evaluator cost caps, fence late calls, and pass
    remaining per-case timeout budgets directly to provider calls.
    """

    def __init__(
        self,
        inner_port: RuntimeModelPort,
        *,
        max_cost_usd: float,
        cost_per_call_usd: float = 0.002,
    ) -> None:
        self._inner = inner_port
        self.max_cost_usd = max_cost_usd
        self.cost_per_call_usd = cost_per_call_usd
        self._lock = threading.Lock()
        self.calls_made = 0
        self.spent_usd = 0.0
        self.timeout_budgets_s: list[float] = []
        self._case_deadline_monotonic: float | None = None
        self._timeout_param_name = self._detect_timeout_param(inner_port)

    @staticmethod
    def _detect_timeout_param(port: Any) -> str | None:
        fn = getattr(port, "complete_json", None)
        if not callable(fn):
            return None
        try:
            sig = inspect.signature(fn)
            for name in ("timeout", "timeout_seconds", "request_timeout"):
                if name in sig.parameters:
                    return name
            if any(
                p.kind == inspect.Parameter.VAR_KEYWORD
                for p in sig.parameters.values()
            ):
                return "timeout"
        except Exception:
            pass
        return None

    def set_case_deadline(self, deadline_monotonic: float | None) -> None:
        self._case_deadline_monotonic = deadline_monotonic

    def invoke_with_fence(
        self,
        fence: AttemptExecutionFence | None,
        *,
        system_prompt: str,
        user_prompt: str,
        output_schema: dict[str, Any],
        model_id: str,
        effort: str,
        max_tokens: int,
    ) -> dict[str, Any]:
        remaining_s: float | None = None
        if fence is not None:
            remaining_s = fence.check_active()
        elif self._case_deadline_monotonic is not None:
            remaining_s = self._case_deadline_monotonic - time.monotonic()
            if remaining_s <= 0:
                raise CaseDeadlineExceededError(
                    "case_wall_timeout_exceeded_before_model_call"
                )

        with self._lock:
            if fence is not None:
                remaining_s = fence.check_active()
            if self.spent_usd + self.cost_per_call_usd > self.max_cost_usd:
                raise EvaluationAbortError(
                    AbortCode.BUDGET_EXCEEDED,
                    audit_detail="eval_cost_cap_exceeded",
                )
            self.calls_made += 1
            self.spent_usd = round(self.spent_usd + self.cost_per_call_usd, 6)
            if remaining_s is not None:
                self.timeout_budgets_s.append(round(remaining_s, 6))

        call_kwargs: dict[str, Any] = {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "output_schema": output_schema,
            "model_id": model_id,
            "effort": effort,
            "max_tokens": max_tokens,
        }
        if remaining_s is not None and self._timeout_param_name is not None:
            call_kwargs[self._timeout_param_name] = max(0.001, remaining_s)

        result = self._inner.complete_json(**call_kwargs)

        if fence is not None:
            fence.check_active()
        elif (
            self._case_deadline_monotonic is not None
            and time.monotonic() >= self._case_deadline_monotonic
        ):
            raise CaseDeadlineExceededError(
                "case_wall_timeout_exceeded_after_model_call"
            )
        return result

    def complete_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        output_schema: dict[str, Any],
        model_id: str,
        effort: str,
        max_tokens: int,
    ) -> dict[str, Any]:
        return self.invoke_with_fence(
            None,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            output_schema=output_schema,
            model_id=model_id,
            effort=effort,
            max_tokens=max_tokens,
        )


class _AttemptScopedModelPort:
    """Per-attempt RuntimeModelPort adapter bound to an AttemptExecutionFence."""

    def __init__(
        self,
        metered_port: MeteredEvalModelPort,
        fence: AttemptExecutionFence,
    ) -> None:
        self._metered = metered_port
        self._fence = fence

    def complete_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        output_schema: dict[str, Any],
        model_id: str,
        effort: str,
        max_tokens: int,
    ) -> dict[str, Any]:
        return self._metered.invoke_with_fence(
            self._fence,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            output_schema=output_schema,
            model_id=model_id,
            effort=effort,
            max_tokens=max_tokens,
        )


@dataclass
class IsolatedEvalEnvironment:
    temp_dir: tempfile.TemporaryDirectory[str]
    scratch_storage: StorageService
    sandbox_verifier: SandboxVerifier
    metered_model_port: MeteredEvalModelPort
    runtime: AppRuntime
    case_run_counter: int = 0
    _active_fence: AttemptExecutionFence | None = field(default=None, repr=False)

    def create_attempt_runtime(
        self,
        fence: AttemptExecutionFence,
        *,
        memory_mb: int = 256,
    ) -> AppRuntime:
        """Creates a dedicated, fenced StorageService and AppRuntime for a single execution attempt.

        Prevents any timed-out background thread from a previous attempt or case from accessing
        or mutating the storage or runtime used by subsequent retries or cases.
        """
        if self._active_fence is not None:
            self._active_fence.revoke()
        self._active_fence = fence

        rem_s = fence.check_active()
        base_root = Path(self.temp_dir.name)
        self.case_run_counter += 1
        fresh_root = (
            base_root
            / f"case_store_{self.case_run_counter}_{uuid.uuid4().hex[:8]}"
        )
        fresh_storage = StorageService(StorageConfig(fresh_root))
        fresh_storage.initialize()
        fenced_storage = _FencedAttemptStorage(fresh_storage, fence)

        base_sbx_cfg = self.sandbox_verifier.config
        scoped_sbx_cfg = SandboxConfig(
            max_generated_code_bytes=int(
                getattr(base_sbx_cfg, "max_generated_code_bytes", 100_000)
            ),
            sandbox_timeout_seconds=max(1, int(math.ceil(rem_s))),
            sandbox_memory_mb=max(32, int(memory_mb)),
            prefer_docker_sandbox=bool(
                getattr(base_sbx_cfg, "prefer_docker_sandbox", True)
            ),
            allow_subprocess_dev_fallback=bool(
                getattr(base_sbx_cfg, "allow_subprocess_dev_fallback", False)
            ),
        )
        attempt_verifier = SandboxVerifier(
            scoped_sbx_cfg,
            docker_runner_override=self.sandbox_verifier.docker_runner_override,
        )
        if hasattr(self.sandbox_verifier, "_docker_available"):
            attempt_verifier._docker_available = (  # type: ignore[method-assign]
                self.sandbox_verifier._docker_available
            )

        attempt_model_port = _AttemptScopedModelPort(
            self.metered_model_port, fence
        )
        attempt_runtime = AppRuntime(
            fenced_storage,  # type: ignore[arg-type]
            attempt_verifier,
            attempt_model_port,
        )
        self.scratch_storage = fresh_storage
        self.runtime = attempt_runtime
        return attempt_runtime

    def reset_case_storage(self) -> StorageService:
        """Resets application storage in a fresh isolated directory and revokes any prior fence."""
        if self._active_fence is not None:
            self._active_fence.revoke()
        base_root = Path(self.temp_dir.name)
        self.case_run_counter += 1
        fresh_root = (
            base_root
            / f"case_store_{self.case_run_counter}_{uuid.uuid4().hex[:8]}"
        )
        fresh_storage = StorageService(StorageConfig(fresh_root))
        fresh_storage.initialize()
        self.scratch_storage = fresh_storage
        self.runtime = AppRuntime(
            fresh_storage, self.sandbox_verifier, self.metered_model_port
        )
        return fresh_storage

    def cleanup(self) -> None:
        if self._active_fence is not None:
            self._active_fence.revoke()
        shutil.rmtree(self.temp_dir.name, ignore_errors=True)
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass


class EnvironmentFactory:
    """C4 — Creates isolated scratch StorageService, fail-closed SandboxVerifier, and AppRuntime."""

    @staticmethod
    def _bundle_uses_generated_code(
        manifest: BundleManifest, files_data: Mapping[str, bytes]
    ) -> bool:
        if manifest.architecture == "tool_use" or bool(manifest.allowed_tools):
            return True
        if any(p.startswith("generated/") or p.endswith(".py") for p in files_data):
            return True
        try:
            app_cfg = json.loads(files_data[manifest.entrypoint].decode("utf-8"))
            return any(
                str(s.get("component_ref", "")).startswith("fn.sandboxed@")
                for s in app_cfg.get("steps", [])
            )
        except Exception:
            return False

    @classmethod
    def create(
        cls,
        *,
        manifest: BundleManifest,
        files_data: Mapping[str, bytes],
        model_port: RuntimeModelPort,
        config: EvaluatorConfig,
        docker_runner_override: Callable[..., Any] | None = None,
    ) -> IsolatedEvalEnvironment:
        sbx_cfg = SandboxConfig(
            sandbox_timeout_seconds=int(manifest.limits.wall_seconds),
            sandbox_memory_mb=int(manifest.limits.memory_mb),
            prefer_docker_sandbox=True,
            allow_subprocess_dev_fallback=config.allow_subprocess_sandbox_fallback,
        )
        verifier = SandboxVerifier(
            sbx_cfg, docker_runner_override=docker_runner_override
        )

        if cls._bundle_uses_generated_code(manifest, files_data):
            if (
                not verifier._docker_available()
                and not config.allow_subprocess_sandbox_fallback
            ):
                raise EvaluationAbortError(
                    AbortCode.SANDBOX_UNAVAILABLE,
                    audit_detail="docker_unavailable_for_tool_use_bundle",
                )

        tmp_dir = tempfile.TemporaryDirectory(prefix="adaptos_eval_scratch_")
        scratch_storage = StorageService(
            StorageConfig(Path(tmp_dir.name) / "case_store_0")
        )
        scratch_storage.initialize()

        metered_port = MeteredEvalModelPort(
            model_port, max_cost_usd=config.max_eval_cost_usd
        )
        runtime = AppRuntime(scratch_storage, verifier, metered_port)
        return IsolatedEvalEnvironment(
            temp_dir=tmp_dir,
            scratch_storage=scratch_storage,
            sandbox_verifier=verifier,
            metered_model_port=metered_port,
            runtime=runtime,
            case_run_counter=0,
        )


# =========================================================================== #
# 6. C5 CASE EXECUTOR, C6 CASE GRADER & C6b JUDGE ADAPTER
# =========================================================================== #


@dataclass(frozen=True)
class CaseExecutionOutcome:
    case_id: str
    status: Literal["ok", "artifact_error", "infra_error"]
    output: dict[str, Any] | None
    error_code: str
    latency_ms: int


class CaseExecutor:
    """C5 — Runs AppRuntime per case with a single absolute case deadline across all retries,
    per-attempt fenced storage/model isolation, and output size cap.

    Note on In-Process Thread Cancellation (Requirement 5):
    When `AppRuntime` executes in-process with a Python `RuntimeModelPort`, Python threads
    cannot be forcibly killed by OS signals without terminating the process. To guarantee safety:
    1. Provider model calls receive the remaining timeout budget directly (`timeout=remaining_s`).
    2. Sandboxed generated functions run in separate Docker/OS processes with clamped timeouts.
    3. Every attempt is wrapped in an `AttemptExecutionFence` with its own isolated storage directory
       and `AppRuntime` instance; upon timeout, `fence.revoke()` immediately blocks any late thread
       from accessing storage or issuing model calls.
    """

    def __init__(self, config: EvaluatorConfig) -> None:
        self.config = config

    def execute_case(
        self,
        *,
        env: IsolatedEvalEnvironment,
        manifest: BundleManifest,
        files_data: Mapping[str, bytes],
        input_data: Mapping[str, Any],
        case_id: str,
        assets: Sequence[SourceAssetInput],
        eval_deadline_monotonic: float | None = None,
    ) -> CaseExecutionOutcome:
        # Required Change 1 & 2: Establish ONE absolute deadline for the entire case execution
        # BEFORE the retry loop. Retries never reset or extend this deadline.
        case_start_t0 = time.monotonic()
        wall_limit_s = float(manifest.limits.wall_seconds)
        case_deadline = case_start_t0 + wall_limit_s
        effective_deadline = (
            min(case_deadline, eval_deadline_monotonic)
            if eval_deadline_monotonic is not None
            else case_deadline
        )

        retries = 0

        while True:
            now = time.monotonic()
            if (
                eval_deadline_monotonic is not None
                and now >= eval_deadline_monotonic
                and eval_deadline_monotonic <= case_deadline
            ):
                raise EvaluationAbortError(
                    AbortCode.BUDGET_EXCEEDED,
                    audit_detail="eval_wall_clock_cap_exceeded",
                )

            remaining_s = effective_deadline - now
            if remaining_s <= 0:
                return CaseExecutionOutcome(
                    case_id=case_id,
                    status="artifact_error",
                    output=None,
                    error_code="case_wall_timeout_exceeded",
                    latency_ms=max(1, int((time.monotonic() - case_start_t0) * 1000)),
                )

            # Required Change 3 & 4: Create a per-attempt execution fence and isolated AppRuntime/Storage
            fence = AttemptExecutionFence(effective_deadline)
            attempt_runtime = env.create_attempt_runtime(
                fence, memory_mb=int(manifest.limits.memory_mb)
            )
            isolated_input = copy.deepcopy(dict(input_data))

            executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            fut = executor.submit(
                attempt_runtime.execute_bundle,
                manifest,
                files_data,
                isolated_input,
                assets=assets,
            )
            try:
                rem_wait_s = effective_deadline - time.monotonic()
                if rem_wait_s <= 0:
                    raise CaseDeadlineExceededError("case_wall_timeout_exceeded")

                out, _ = fut.result(timeout=max(0.001, rem_wait_s))
                total_elapsed_s = time.monotonic() - case_start_t0
                latency_ms = max(1, int(total_elapsed_s * 1000))

                if total_elapsed_s > wall_limit_s or time.monotonic() > case_deadline:
                    return CaseExecutionOutcome(
                        case_id=case_id,
                        status="artifact_error",
                        output=None,
                        error_code="case_wall_timeout_exceeded",
                        latency_ms=latency_ms,
                    )

                serialized_out = _canonical_bytes(out)
                if len(serialized_out) > self.config.max_output_bytes:
                    return CaseExecutionOutcome(
                        case_id=case_id,
                        status="artifact_error",
                        output=None,
                        error_code="case_output_size_exceeded",
                        latency_ms=latency_ms,
                    )

                return CaseExecutionOutcome(
                    case_id=case_id,
                    status="ok",
                    output=out,
                    error_code="ok",
                    latency_ms=latency_ms,
                )

            except (concurrent.futures.TimeoutError, CaseDeadlineExceededError):
                fence.revoke()
                latency_ms = max(1, int((time.monotonic() - case_start_t0) * 1000))
                if (
                    eval_deadline_monotonic is not None
                    and time.monotonic() >= eval_deadline_monotonic
                    and eval_deadline_monotonic < case_deadline
                ):
                    raise EvaluationAbortError(
                        AbortCode.BUDGET_EXCEEDED,
                        audit_detail="eval_wall_clock_cap_exceeded",
                    )
                return CaseExecutionOutcome(
                    case_id=case_id,
                    status="artifact_error",
                    output=None,
                    error_code="case_wall_timeout_exceeded",
                    latency_ms=latency_ms,
                )
            except EvaluationAbortError:
                fence.revoke()
                raise
            except InfrastructureModelError as exc:
                fence.revoke()
                now_after_err = time.monotonic()
                latency_ms = max(1, int((now_after_err - case_start_t0) * 1000))
                rem_after_err = effective_deadline - now_after_err
                if rem_after_err <= 0:
                    if (
                        eval_deadline_monotonic is not None
                        and now_after_err >= eval_deadline_monotonic
                        and eval_deadline_monotonic < case_deadline
                    ):
                        raise EvaluationAbortError(
                            AbortCode.BUDGET_EXCEEDED,
                            audit_detail="eval_wall_clock_cap_exceeded",
                        ) from exc
                    return CaseExecutionOutcome(
                        case_id=case_id,
                        status="artifact_error",
                        output=None,
                        error_code="case_wall_timeout_exceeded",
                        latency_ms=latency_ms,
                    )

                if retries < self.config.max_infra_retries:
                    retries += 1
                    backoff_s = self.config.infra_retry_delay_seconds * (
                        2**retries
                    )
                    if backoff_s >= rem_after_err:
                        time.sleep(max(0.0, rem_after_err))
                        return CaseExecutionOutcome(
                            case_id=case_id,
                            status="artifact_error",
                            output=None,
                            error_code="case_wall_timeout_exceeded",
                            latency_ms=max(
                                1, int((time.monotonic() - case_start_t0) * 1000)
                            ),
                        )
                    time.sleep(backoff_s)
                    continue

                return CaseExecutionOutcome(
                    case_id=case_id,
                    status="infra_error",
                    output=None,
                    error_code=RedactionLayer.sanitize_code_only(type(exc).__name__),
                    latency_ms=latency_ms,
                )
            except (RuntimeExecutionError, Exception) as exc:
                fence.revoke()
                latency_ms = max(1, int((time.monotonic() - case_start_t0) * 1000))
                if (
                    "case_wall_timeout_exceeded" in str(exc)
                    or time.monotonic() >= case_deadline
                ):
                    return CaseExecutionOutcome(
                        case_id=case_id,
                        status="artifact_error",
                        output=None,
                        error_code="case_wall_timeout_exceeded",
                        latency_ms=latency_ms,
                    )
                return CaseExecutionOutcome(
                    case_id=case_id,
                    status="artifact_error",
                    output=None,
                    error_code=RedactionLayer.sanitize_code_only(type(exc).__name__),
                    latency_ms=latency_ms,
                )
            finally:
                fence.revoke()
                executor.shutdown(wait=False, cancel_futures=True)


@dataclass(frozen=True)
class CaseGradeRecord:
    case_id: str
    criterion_id: str
    method: CriterionMethod
    grade_status: Literal["passed", "failed", "ungraded"]
    error_code: str
    latency_ms: int
    case_hash: str = ""
    grader_version: str = GRADER_VERSION
    judge_model: str | None = None


class CaseGrader:
    """C6 & C6b — Stricter deterministic per-method grader + validated blind JudgeAdapter."""

    def __init__(
        self,
        *,
        spec: Spec,
        runtime_model_id: str,
        judge_port: JudgePort | None = None,
    ) -> None:
        self.spec = spec
        self.crit_by_id = {c.criterion_id: c for c in spec.acceptance_criteria}
        self.output_schema = _spec_outputs_to_json_schema(spec.outputs)
        self.runtime_model_id = runtime_model_id
        self.judge_port = judge_port

    def grade_case(
        self,
        case: SealedEvaluationCase,
        exec_outcome: CaseExecutionOutcome,
    ) -> CaseGradeRecord:
        c_hash = case.compute_case_hash()

        if exec_outcome.status == "infra_error":
            return CaseGradeRecord(
                case_id=case.case_id,
                criterion_id=case.criterion_id,
                method=case.method,
                grade_status="ungraded",
                error_code=f"infra:{exec_outcome.error_code}",
                latency_ms=exec_outcome.latency_ms,
                case_hash=c_hash,
                grader_version=GRADER_VERSION,
            )

        if exec_outcome.status == "artifact_error" or exec_outcome.output is None:
            return CaseGradeRecord(
                case_id=case.case_id,
                criterion_id=case.criterion_id,
                method=case.method,
                grade_status="failed",
                error_code=f"artifact:{exec_outcome.error_code}",
                latency_ms=exec_outcome.latency_ms,
                case_hash=c_hash,
                grader_version=GRADER_VERSION,
            )

        output = exec_outcome.output
        method = case.method

        if method == "schema_valid":
            if not self.output_schema.get(
                "properties"
            ) and not self.output_schema.get("required"):
                return CaseGradeRecord(
                    case_id=case.case_id,
                    criterion_id=case.criterion_id,
                    method=method,
                    grade_status="failed",
                    error_code="empty_output_schema_definition",
                    latency_ms=exec_outcome.latency_ms,
                    case_hash=c_hash,
                    grader_version=GRADER_VERSION,
                )
            errs = SandboxVerifier.validate_output_against_schema(
                output, self.output_schema
            )
            return CaseGradeRecord(
                case_id=case.case_id,
                criterion_id=case.criterion_id,
                method=method,
                grade_status="passed" if not errs else "failed",
                error_code="ok" if not errs else "schema_validation_failed",
                latency_ms=exec_outcome.latency_ms,
                case_hash=c_hash,
                grader_version=GRADER_VERSION,
            )

        if method == "exact_match":
            for tf in case.target_fields:
                if tf not in output:
                    return CaseGradeRecord(
                        case_id=case.case_id,
                        criterion_id=case.criterion_id,
                        method=method,
                        grade_status="failed",
                        error_code=f"missing_target_field:{tf}",
                        latency_ms=exec_outcome.latency_ms,
                        case_hash=c_hash,
                        grader_version=GRADER_VERSION,
                    )
                if not _strict_typed_equal(output[tf], case.expected_output[tf]):
                    return CaseGradeRecord(
                        case_id=case.case_id,
                        criterion_id=case.criterion_id,
                        method=method,
                        grade_status="failed",
                        error_code=f"exact_match_failed:{tf}",
                        latency_ms=exec_outcome.latency_ms,
                        case_hash=c_hash,
                        grader_version=GRADER_VERSION,
                    )
            return CaseGradeRecord(
                case_id=case.case_id,
                criterion_id=case.criterion_id,
                method=method,
                grade_status="passed",
                error_code="ok",
                latency_ms=exec_outcome.latency_ms,
                case_hash=c_hash,
                grader_version=GRADER_VERSION,
            )

        if method == "contains":
            for tf in case.target_fields:
                if tf not in output or not isinstance(output[tf], str):
                    return CaseGradeRecord(
                        case_id=case.case_id,
                        criterion_id=case.criterion_id,
                        method=method,
                        grade_status="failed",
                        error_code=f"non_string_or_missing_target_field:{tf}",
                        latency_ms=exec_outcome.latency_ms,
                        case_hash=c_hash,
                        grader_version=GRADER_VERSION,
                    )
                expected_sub = str(case.expected_output[tf]).strip().lower()
                actual_str = output[tf].lower()
                if not expected_sub or expected_sub not in actual_str:
                    return CaseGradeRecord(
                        case_id=case.case_id,
                        criterion_id=case.criterion_id,
                        method=method,
                        grade_status="failed",
                        error_code=f"contains_mismatch:{tf}",
                        latency_ms=exec_outcome.latency_ms,
                        case_hash=c_hash,
                        grader_version=GRADER_VERSION,
                    )
            return CaseGradeRecord(
                case_id=case.case_id,
                criterion_id=case.criterion_id,
                method=method,
                grade_status="passed",
                error_code="ok",
                latency_ms=exec_outcome.latency_ms,
                case_hash=c_hash,
                grader_version=GRADER_VERSION,
            )

        if method == "numeric_tolerance":
            for tf in case.target_fields:
                exp_val = case.expected_output.get(tf)
                if not isinstance(exp_val, (int, float)) or isinstance(exp_val, bool):
                    raise EvaluationAbortError(
                        AbortCode.SEALED_SET_INVALID,
                        audit_detail=f"non_numeric_expected_value:{tf}",
                    )
                act_val = output.get(tf)
                if not isinstance(act_val, (int, float)) or isinstance(act_val, bool):
                    return CaseGradeRecord(
                        case_id=case.case_id,
                        criterion_id=case.criterion_id,
                        method=method,
                        grade_status="failed",
                        error_code=f"non_numeric_actual_value:{tf}",
                        latency_ms=exec_outcome.latency_ms,
                        case_hash=c_hash,
                        grader_version=GRADER_VERSION,
                    )
                if abs(float(act_val) - float(exp_val)) > case.numeric_tolerance:
                    return CaseGradeRecord(
                        case_id=case.case_id,
                        criterion_id=case.criterion_id,
                        method=method,
                        grade_status="failed",
                        error_code=f"numeric_tolerance_exceeded:{tf}",
                        latency_ms=exec_outcome.latency_ms,
                        case_hash=c_hash,
                        grader_version=GRADER_VERSION,
                    )
            return CaseGradeRecord(
                case_id=case.case_id,
                criterion_id=case.criterion_id,
                method=method,
                grade_status="passed",
                error_code="ok",
                latency_ms=exec_outcome.latency_ms,
                case_hash=c_hash,
                grader_version=GRADER_VERSION,
            )

        if method == "rubric":
            schema_errs = SandboxVerifier.validate_output_against_schema(
                output, self.output_schema
            )
            if schema_errs:
                return CaseGradeRecord(
                    case_id=case.case_id,
                    criterion_id=case.criterion_id,
                    method=method,
                    grade_status="failed",
                    error_code="rubric_deterministic_schema_failed",
                    latency_ms=exec_outcome.latency_ms,
                    case_hash=c_hash,
                    grader_version=GRADER_VERSION,
                )

            if self.judge_port is None:
                return CaseGradeRecord(
                    case_id=case.case_id,
                    criterion_id=case.criterion_id,
                    method=method,
                    grade_status="ungraded",
                    error_code="judge_unavailable",
                    latency_ms=exec_outcome.latency_ms,
                    case_hash=c_hash,
                    grader_version=GRADER_VERSION,
                )

            runtime_norm = str(self.runtime_model_id or "").strip().lower()
            configured_judge = str(
                getattr(self.judge_port, "judge_model_id", "") or ""
            ).strip()
            if not configured_judge or configured_judge.lower() == runtime_norm:
                return CaseGradeRecord(
                    case_id=case.case_id,
                    criterion_id=case.criterion_id,
                    method=method,
                    grade_status="ungraded",
                    error_code="judge_same_as_runtime_model",
                    latency_ms=exec_outcome.latency_ms,
                    case_hash=c_hash,
                    grader_version=GRADER_VERSION,
                )

            required_dim_ids: set[str] = set()
            for dim in case.rubric_dimensions:
                if isinstance(dim, Mapping):
                    did = str(dim.get("id") or dim.get("dimension_id") or "").strip()
                    if did:
                        required_dim_ids.add(did)
            if not required_dim_ids:
                return CaseGradeRecord(
                    case_id=case.case_id,
                    criterion_id=case.criterion_id,
                    method=method,
                    grade_status="ungraded",
                    error_code="rubric_missing_dimensions",
                    latency_ms=exec_outcome.latency_ms,
                    case_hash=c_hash,
                    grader_version=GRADER_VERSION,
                )

            crit_desc = self.crit_by_id[case.criterion_id].description
            filtered_out = {tf: output.get(tf) for tf in case.target_fields}
            try:
                j_verdict = self.judge_port.evaluate_rubric(
                    criterion_description=crit_desc,
                    dimensions=case.rubric_dimensions,
                    input_data=case.input_data,
                    output_data=filtered_out,
                )
            except Exception as exc:
                return CaseGradeRecord(
                    case_id=case.case_id,
                    criterion_id=case.criterion_id,
                    method=method,
                    grade_status="ungraded",
                    error_code=f"judge_error:{RedactionLayer.sanitize_code_only(type(exc).__name__)}",
                    latency_ms=exec_outcome.latency_ms,
                    case_hash=c_hash,
                    grader_version=GRADER_VERSION,
                )

            returned_judge = str(getattr(j_verdict, "judge_model", "") or "").strip()
            if (
                not returned_judge
                or returned_judge != configured_judge
                or returned_judge.lower() == runtime_norm
            ):
                return CaseGradeRecord(
                    case_id=case.case_id,
                    criterion_id=case.criterion_id,
                    method=method,
                    grade_status="ungraded",
                    error_code="judge_identity_invalid_or_same_as_runtime",
                    latency_ms=exec_outcome.latency_ms,
                    case_hash=c_hash,
                    grader_version=GRADER_VERSION,
                )

            dim_scores = getattr(j_verdict, "dimension_scores", None)
            if (
                not isinstance(dim_scores, Mapping)
                or set(dim_scores.keys()) != required_dim_ids
                or any(
                    not isinstance(v, int) or isinstance(v, bool) or v not in (0, 1)
                    for v in dim_scores.values()
                )
            ):
                return CaseGradeRecord(
                    case_id=case.case_id,
                    criterion_id=case.criterion_id,
                    method=method,
                    grade_status="ungraded",
                    error_code="judge_invalid_dimension_scores",
                    latency_ms=exec_outcome.latency_ms,
                    case_hash=c_hash,
                    grader_version=GRADER_VERSION,
                )

            all_dims_passed = all(v == 1 for v in dim_scores.values())
            if bool(j_verdict.passed) != all_dims_passed:
                return CaseGradeRecord(
                    case_id=case.case_id,
                    criterion_id=case.criterion_id,
                    method=method,
                    grade_status="ungraded",
                    error_code="judge_dimension_pass_disagreement",
                    latency_ms=exec_outcome.latency_ms,
                    case_hash=c_hash,
                    grader_version=GRADER_VERSION,
                )

            return CaseGradeRecord(
                case_id=case.case_id,
                criterion_id=case.criterion_id,
                method=method,
                grade_status="passed" if j_verdict.passed else "failed",
                error_code="ok" if j_verdict.passed else "judge_rubric_failed",
                latency_ms=exec_outcome.latency_ms,
                case_hash=c_hash,
                grader_version=GRADER_VERSION,
                judge_model=returned_judge,
            )

        raise EvaluationAbortError(
            AbortCode.SEALED_SET_INVALID, audit_detail=f"unsupported_method:{method}"
        )


# =========================================================================== #
# 7. C7 AGGREGATOR, C8 VERDICT BUILDER & SIGNER, C9 EVIDENCE, C10 LEDGER
# =========================================================================== #


class Aggregator:
    """C7 — Counts per criterion and enforces that every sealed case is graded or handled."""

    @staticmethod
    def aggregate(
        *,
        spec: Spec,
        sealed_cases: Sequence[SealedEvaluationCase],
        grade_records: Mapping[str, CaseGradeRecord],
    ) -> tuple[dict[str, tuple[int, int]], list[str], str | None]:
        if set(grade_records.keys()) != {c.case_id for c in sealed_cases}:
            raise EvaluationAbortError(
                AbortCode.EVALUATION_INCOMPLETE,
                audit_detail="missing_case_grade_records",
            )

        counts: dict[str, tuple[int, int]] = {}
        non_rubric_ungraded: list[str] = []
        detected_judge_model: str | None = None

        cases_by_crit: dict[str, list[SealedEvaluationCase]] = {
            c.criterion_id: [] for c in spec.acceptance_criteria
        }
        for tc in sealed_cases:
            cases_by_crit[tc.criterion_id].append(tc)

        for crit in spec.acceptance_criteria:
            cid = crit.criterion_id
            crit_cases = cases_by_crit[cid]
            passed_count = 0
            graded_count = 0
            ungraded_for_crit = 0

            for tc in crit_cases:
                rec = grade_records[tc.case_id]
                if rec.judge_model:
                    detected_judge_model = rec.judge_model
                if rec.grade_status == "passed":
                    passed_count += 1
                    graded_count += 1
                elif rec.grade_status == "failed":
                    graded_count += 1
                else:
                    ungraded_for_crit += 1
                    if crit.method != "rubric":
                        non_rubric_ungraded.append(tc.case_id)

            if crit.method == "rubric" and ungraded_for_crit > 0:
                counts[cid] = (0, 0)
            else:
                counts[cid] = (passed_count, graded_count)

        return counts, non_rubric_ungraded, detected_judge_model


class VerdictBuilderAndSigner:
    """C8 — Builds CriterionResults, assembles Verdict, signs at Step S11, and self-verifies."""

    @staticmethod
    def _build_criterion_result(
        crit: AcceptanceCriterion, n_passed: int, n_cases: int
    ) -> CriterionResult:
        # schemas.CriterionResult.from_counts derives pass_rate and the Wilson
        # confidence interval from the counts and refuses inconsistent stats.
        if n_cases == 0:
            return CriterionResult.from_counts(
                criterion_id=crit.criterion_id,
                threshold=crit.min_pass_rate,
                n_passed=0,
                n_cases=0,
            )
        return CriterionResult.from_counts(
            criterion_id=crit.criterion_id,
            threshold=crit.min_pass_rate,
            n_passed=n_passed,
            n_cases=n_cases,
        )

    @staticmethod
    def _derive_verdict_status(
        criterion_results: Sequence[CriterionResult],
    ) -> str:
        statuses = [getattr(cr, "status", None) for cr in criterion_results]
        v_status_ann = str(Verdict.model_fields["status"].annotation)
        insuff_label = (
            "insufficient_evidence"
            if "insufficient_evidence" in v_status_ann
            else "insufficient"
        )
        if any(s == "not_met" for s in statuses):
            return "not_ready"
        if any(s == "undetermined" for s in statuses) or not criterion_results:
            return insuff_label
        return "ready"

    @classmethod
    def build_and_sign(
        cls,
        *,
        spec: Spec,
        artifact_ref: ArtifactRef,
        commitment: SealedSetCommitment,
        counts_by_criterion: Mapping[str, tuple[int, int]],
        evidence_hash: str,
        judge_model: str | None,
        signer: SignerPort,
        clock: ClockPort,
    ) -> Verdict:
        crit_results: list[CriterionResult] = []
        for crit in spec.acceptance_criteria:
            n_pass, n_tot = counts_by_criterion[crit.criterion_id]
            crit_results.append(cls._build_criterion_result(crit, n_pass, n_tot))

        derived_status = cls._derive_verdict_status(crit_results)
        verdict_kwargs: dict[str, Any] = {
            "verdict_id": f"verdict_{uuid.uuid4().hex[:12]}",
            "spec_hash": spec.content_hash(),
            "artifact": artifact_ref,
            "sealed_set_id": commitment.set_id,
            "sealed_commitment_hash": commitment.commitment_hash,
            "status": derived_status,
            "criteria": tuple(crit_results),
            "evidence_hash": evidence_hash,
            "issued_at": clock.now_utc(),
            "signing_key_id": signer.key_id,
            "signature": "0" * 128,
        }
        if "judge_model" in Verdict.model_fields and judge_model is not None:
            verdict_kwargs["judge_model"] = judge_model

        unsigned_verdict = Verdict(**verdict_kwargs)

        payload_bytes = unsigned_verdict.signing_payload()
        sig_hex = signer.sign(payload_bytes)
        signed_verdict = Verdict.model_validate(
            {**unsigned_verdict.model_dump(mode="json"), "signature": sig_hex}
        )

        if not Ed25519Signer.verify_signature(
            signer.public_key_bytes,
            signed_verdict.signing_payload(),
            signed_verdict.signature,
        ):
            raise EvaluationAbortError(
                AbortCode.SIGNING_UNAVAILABLE,
                audit_detail="self_signature_verification_failed",
            )
        return signed_verdict


class EvidenceRecorder:
    """C9 — Writes private per-case evidence to eval DB and returns canonical evidence_hash."""

    def __init__(self, eval_db_path: Path) -> None:
        self.eval_db_path = Path(eval_db_path)

    def record_evidence(
        self,
        *,
        eval_key: str,
        spec_hash: str,
        artifact_hash: str,
        sealed_set_id: str,
        sealed_commitment_hash: str,
        grade_records: Mapping[str, CaseGradeRecord],
    ) -> str:
        ordered_records = [
            {
                "case_id": cid,
                "criterion_id": rec.criterion_id,
                "method": rec.method,
                "case_hash": rec.case_hash,
                "grader_version": rec.grader_version,
                "grade_status": rec.grade_status,
                "error_code": rec.error_code,
                "latency_ms": rec.latency_ms,
                "judge_model": rec.judge_model,
            }
            for cid, rec in sorted(grade_records.items(), key=lambda item: item[0])
        ]
        evidence_payload = {
            "grader_version": GRADER_VERSION,
            "spec_hash": spec_hash,
            "artifact_hash": artifact_hash,
            "sealed_set_id": sealed_set_id,
            "sealed_commitment_hash": sealed_commitment_hash,
            "case_records": ordered_records,
        }
        evidence_bytes = _canonical_bytes(evidence_payload)
        evidence_hash = sha256_hex(evidence_bytes)

        try:
            with sqlite3.connect(self.eval_db_path, timeout=10.0) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO eval_evidence_store
                    (evidence_hash, eval_key, grader_version, payload_json, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        evidence_hash,
                        eval_key,
                        GRADER_VERSION,
                        evidence_bytes.decode("utf-8"),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
        except Exception as exc:
            raise EvaluationAbortError(
                AbortCode.EVIDENCE_STORE_UNAVAILABLE,
                audit_detail=type(exc).__name__,
            ) from exc

        return evidence_hash


class EvaluationLedger:
    """C10 — Durable state machine, atomic per-set budget reservation, and validated crash recovery."""

    def __init__(self, eval_db_path: Path, *, max_evaluations_per_set: int = 1) -> None:
        self.eval_db_path = Path(eval_db_path)
        self.max_evaluations_per_set = max_evaluations_per_set
        self._init_db()

    def _init_db(self) -> None:
        try:
            self.eval_db_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.eval_db_path, timeout=10.0) as conn:
                conn.executescript("""
                    PRAGMA journal_mode=WAL;
                    CREATE TABLE IF NOT EXISTS eval_ledger (
                        eval_key TEXT PRIMARY KEY,
                        artifact_hash TEXT NOT NULL,
                        spec_hash TEXT NOT NULL,
                        sealed_set_id TEXT NOT NULL,
                        state TEXT NOT NULL,
                        abort_code TEXT,
                        verdict_json TEXT,
                        updated_at TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS eval_case_progress (
                        eval_key TEXT NOT NULL,
                        case_id TEXT NOT NULL,
                        criterion_id TEXT NOT NULL,
                        method TEXT NOT NULL,
                        case_hash TEXT NOT NULL,
                        grader_version TEXT NOT NULL,
                        grade_status TEXT NOT NULL,
                        error_code TEXT NOT NULL,
                        latency_ms INTEGER NOT NULL,
                        judge_model TEXT,
                        PRIMARY KEY (eval_key, case_id)
                    );
                    CREATE TABLE IF NOT EXISTS eval_evidence_store (
                        evidence_hash TEXT PRIMARY KEY,
                        eval_key TEXT NOT NULL,
                        grader_version TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );
                """)
        except Exception as exc:
            raise EvaluationAbortError(
                AbortCode.EVIDENCE_STORE_UNAVAILABLE,
                audit_detail=type(exc).__name__,
            ) from exc

    @staticmethod
    def make_eval_key(artifact_hash: str, spec_hash: str, sealed_set_id: str) -> str:
        return f"{artifact_hash}:{spec_hash}:{sealed_set_id}"

    def check_s2_gate_and_begin(
        self,
        *,
        artifact_hash: str,
        spec_hash: str,
        sealed_set_id: str,
    ) -> Verdict | None:
        """Atomically reserves sealed-set evaluation budget inside BEGIN IMMEDIATE."""
        eval_key = self.make_eval_key(artifact_hash, spec_hash, sealed_set_id)
        now_iso = datetime.now(timezone.utc).isoformat()

        conn = sqlite3.connect(
            self.eval_db_path, timeout=10.0, isolation_level=None
        )
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT state, verdict_json FROM eval_ledger WHERE eval_key=?",
                (eval_key,),
            ).fetchone()

            if row is not None:
                state_val = str(row["state"])
                if state_val == LedgerState.STORED.value and row["verdict_json"]:
                    conn.execute("COMMIT")
                    return Verdict.model_validate(json.loads(row["verdict_json"]))
                if state_val in (
                    LedgerState.RECEIVED.value,
                    LedgerState.BOUND.value,
                    LedgerState.EXECUTING.value,
                    LedgerState.GRADED.value,
                    LedgerState.SIGNED.value,
                ):
                    conn.execute("ROLLBACK")
                    raise EvaluationAbortError(
                        AbortCode.EVALUATION_IN_PROGRESS,
                        audit_detail="concurrent_evaluation_active",
                    )

            reserved_rows = conn.execute(
                """
                SELECT DISTINCT artifact_hash FROM eval_ledger
                WHERE sealed_set_id=? AND artifact_hash != ?
                  AND (
                      state IN ('received', 'bound', 'executing', 'graded', 'signed', 'resumable', 'stored')
                      OR eval_key IN (SELECT DISTINCT eval_key FROM eval_case_progress)
                  )
                """,
                (sealed_set_id, artifact_hash),
            ).fetchall()
            if len(reserved_rows) >= self.max_evaluations_per_set:
                conn.execute("ROLLBACK")
                raise EvaluationAbortError(
                    AbortCode.SEALED_SET_EXHAUSTED,
                    audit_detail="sealed_set_evaluation_budget_exhausted",
                )

            conn.execute(
                """
                INSERT OR REPLACE INTO eval_ledger
                (eval_key, artifact_hash, spec_hash, sealed_set_id, state, abort_code, verdict_json, updated_at)
                VALUES (?, ?, ?, ?, ?, NULL, NULL, ?)
                """,
                (
                    eval_key,
                    artifact_hash,
                    spec_hash,
                    sealed_set_id,
                    LedgerState.BOUND.value,
                    now_iso,
                ),
            )
            conn.execute("COMMIT")
            return None
        except EvaluationAbortError:
            raise
        except Exception as exc:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise EvaluationAbortError(
                AbortCode.EVIDENCE_STORE_UNAVAILABLE,
                audit_detail=type(exc).__name__,
            ) from exc
        finally:
            conn.close()

    def set_state(
        self,
        eval_key: str,
        state: LedgerState,
        *,
        abort_code: AbortCode | None = None,
        verdict: Verdict | None = None,
    ) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        v_json = (
            _canonical_bytes(verdict.model_dump(mode="json")).decode("utf-8")
            if verdict is not None
            else None
        )
        with sqlite3.connect(self.eval_db_path, timeout=10.0) as conn:
            conn.execute(
                """
                UPDATE eval_ledger
                SET state=?, abort_code=?, verdict_json=COALESCE(?, verdict_json), updated_at=?
                WHERE eval_key=?
                """,
                (
                    state.value,
                    abort_code.value if abort_code else None,
                    v_json,
                    now_iso,
                    eval_key,
                ),
            )

    def load_validated_case_grades(
        self,
        *,
        eval_key: str,
        sealed_cases: Sequence[SealedEvaluationCase],
        runtime_model_id: str,
    ) -> dict[str, CaseGradeRecord]:
        """Validates every persisted grade record against its corresponding SealedEvaluationCase."""
        try:
            with sqlite3.connect(self.eval_db_path, timeout=10.0) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    """
                    SELECT * FROM eval_case_progress
                    WHERE eval_key=? AND grade_status IN ('passed', 'failed')
                    """,
                    (eval_key,),
                ).fetchall()
        except Exception as exc:
            raise EvaluationAbortError(
                AbortCode.EVIDENCE_STORE_UNAVAILABLE,
                audit_detail=type(exc).__name__,
            ) from exc

        cases_by_id = {tc.case_id: tc for tc in sealed_cases}
        runtime_norm = str(runtime_model_id or "").strip().lower()
        validated: dict[str, CaseGradeRecord] = {}

        for r in rows:
            cid = str(r["case_id"])
            if cid not in cases_by_id:
                raise EvaluationAbortError(
                    AbortCode.EVIDENCE_STORE_UNAVAILABLE,
                    audit_detail="persisted_grade_unknown_case_id",
                )
            tc = cases_by_id[cid]
            expected_case_hash = tc.compute_case_hash()

            if (
                str(r["criterion_id"]) != tc.criterion_id
                or str(r["method"]) != tc.method
                or str(r["case_hash"]) != expected_case_hash
                or str(r["case_hash"]) != tc.input_signature_hash
                or str(r["grader_version"]) != GRADER_VERSION
                or str(r["grade_status"]) not in ("passed", "failed")
                or int(r["latency_ms"]) < 0
            ):
                raise EvaluationAbortError(
                    AbortCode.EVIDENCE_STORE_UNAVAILABLE,
                    audit_detail="persisted_grade_record_mismatch_against_sealed_case",
                )

            j_model = r["judge_model"]
            if tc.method == "rubric":
                if (
                    not j_model
                    or not str(j_model).strip()
                    or str(j_model).strip().lower() == runtime_norm
                ):
                    raise EvaluationAbortError(
                        AbortCode.EVIDENCE_STORE_UNAVAILABLE,
                        audit_detail="persisted_rubric_grade_invalid_judge_model",
                    )

            validated[cid] = CaseGradeRecord(
                case_id=cid,
                criterion_id=str(r["criterion_id"]),
                method=r["method"],
                grade_status=r["grade_status"],
                error_code=str(r["error_code"]),
                latency_ms=int(r["latency_ms"]),
                case_hash=str(r["case_hash"]),
                grader_version=str(r["grader_version"]),
                judge_model=str(j_model) if j_model is not None else None,
            )

        return validated

    def save_case_grade(self, eval_key: str, rec: CaseGradeRecord) -> None:
        with sqlite3.connect(self.eval_db_path, timeout=10.0) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO eval_case_progress
                (eval_key, case_id, criterion_id, method, case_hash, grader_version,
                 grade_status, error_code, latency_ms, judge_model)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    eval_key,
                    rec.case_id,
                    rec.criterion_id,
                    rec.method,
                    rec.case_hash,
                    rec.grader_version,
                    rec.grade_status,
                    rec.error_code,
                    rec.latency_ms,
                    rec.judge_model,
                ),
            )


# =========================================================================== #
# 8. EVALUATOR COORDINATOR (Steps S1–S12 Orchestration)
# =========================================================================== #


class EvaluatorCoordinator:
    """Protected Evaluation Plane Coordinator executing Steps S1 through S12."""

    def __init__(
        self,
        *,
        config: EvaluatorConfig,
        vault_port: VaultReaderPort,
        runtime_model_port: RuntimeModelPort,
        signer: SignerPort,
        judge_port: JudgePort | None = None,
        clock: ClockPort | None = None,
        docker_runner_override: Callable[..., Any] | None = None,
        env_override: Mapping[str, str] | None = None,
    ) -> None:
        BootGuard.verify_startup(config, signer, env=env_override)
        self.config = config
        self.vault_reader = SealedSetReader(vault_port)
        self.runtime_model_port = runtime_model_port
        self.signer = signer
        self.judge_port = judge_port
        self.clock = clock or SystemUTCClock()
        self.docker_runner_override = docker_runner_override
        self.ledger = EvaluationLedger(
            config.eval_db_path,
            max_evaluations_per_set=config.max_evaluations_per_set,
        )
        self.evidence_recorder = EvidenceRecorder(config.eval_db_path)
        self.case_executor = CaseExecutor(config)

    def evaluate_job(self, job: EvaluationJob) -> EvaluationOutcome:
        t0 = time.monotonic()
        eval_deadline = t0 + float(self.config.max_eval_wall_seconds)
        eval_key: str | None = None

        try:
            # Step S1: Bind & verify envelope
            SubmissionVerifier.verify_s1_binding(job)

            artifact_hash = job.manifest.artifact_hash
            spec_hash = job.spec.content_hash()
            sealed_set_id = job.request.sealed.set_id
            eval_key = self.ledger.make_eval_key(
                artifact_hash, spec_hash, sealed_set_id
            )

            # Step S2: Ledger gate (idempotency & atomic per-set budget reservation)
            stored_verdict = self.ledger.check_s2_gate_and_begin(
                artifact_hash=artifact_hash,
                spec_hash=spec_hash,
                sealed_set_id=sealed_set_id,
            )
            if stored_verdict is not None:
                return EvaluationOutcome(
                    status="verdict_issued",
                    verdict=stored_verdict,
                    audit_code="cached_verdict_returned",
                )

            # Step S3: Load & verify artifact integrity in memory
            ArtifactLoader.verify_bundle(job.manifest, job.files_data)

            # Step S4: Open sealed set and verify full-case hashes, commitment & coverage
            sealed_cases = self.vault_reader.read_and_verify(
                expected_commitment=job.request.sealed,
                spec=job.spec,
            )

            # Step S5: Prepare isolated scratch environment
            env = EnvironmentFactory.create(
                manifest=job.manifest,
                files_data=job.files_data,
                model_port=self.runtime_model_port,
                config=self.config,
                docker_runner_override=self.docker_runner_override,
            )
            try:
                self.ledger.set_state(eval_key, LedgerState.EXECUTING)

                grade_records: dict[str, CaseGradeRecord] = (
                    self.ledger.load_validated_case_grades(
                        eval_key=eval_key,
                        sealed_cases=sealed_cases,
                        runtime_model_id=job.manifest.runtime_model,
                    )
                )
                grader = CaseGrader(
                    spec=job.spec,
                    runtime_model_id=job.manifest.runtime_model,
                    judge_port=self.judge_port,
                )

                # Step S6 & S7: Execute ungraded cases (with single per-case deadline & fenced storage) & Grade
                for tc in sealed_cases:
                    if time.monotonic() >= eval_deadline:
                        raise EvaluationAbortError(
                            AbortCode.BUDGET_EXCEEDED,
                            audit_detail="eval_wall_clock_cap_exceeded",
                        )

                    if tc.case_id in grade_records:
                        continue

                    exec_out = self.case_executor.execute_case(
                        env=env,
                        manifest=job.manifest,
                        files_data=job.files_data,
                        input_data=tc.input_data,
                        case_id=tc.case_id,
                        assets=job.assets,
                        eval_deadline_monotonic=eval_deadline,
                    )
                    grade_rec = grader.grade_case(tc, exec_out)
                    grade_records[tc.case_id] = grade_rec
                    self.ledger.save_case_grade(eval_key, grade_rec)
            finally:
                env.cleanup()

            # Step S9: Aggregate counts and check for ungraded non-rubric cases
            counts_by_crit, non_rubric_ungraded, judge_model_used = (
                Aggregator.aggregate(
                    spec=job.spec,
                    sealed_cases=sealed_cases,
                    grade_records=grade_records,
                )
            )
            if non_rubric_ungraded:
                if self.config.allow_resumable_incomplete:
                    self.ledger.set_state(
                        eval_key,
                        LedgerState.RESUMABLE,
                        abort_code=AbortCode.EVALUATION_INCOMPLETE,
                    )
                else:
                    self.ledger.set_state(
                        eval_key,
                        LedgerState.ABORTED,
                        abort_code=AbortCode.EVALUATION_INCOMPLETE,
                    )
                return EvaluationOutcome(
                    status="aborted",
                    abort_code=AbortCode.EVALUATION_INCOMPLETE,
                    audit_code="ungraded_cases_remaining",
                )

            self.ledger.set_state(eval_key, LedgerState.GRADED)

            # Step S8: Record private evidence durably and obtain evidence_hash
            evidence_hash = self.evidence_recorder.record_evidence(
                eval_key=eval_key,
                spec_hash=spec_hash,
                artifact_hash=artifact_hash,
                sealed_set_id=sealed_set_id,
                sealed_commitment_hash=job.request.sealed.commitment_hash,
                grade_records=grade_records,
            )

            # Step S10 & S11: Build Verdict, Sign with Ed25519, and Self-Verify
            signed_verdict = VerdictBuilderAndSigner.build_and_sign(
                spec=job.spec,
                artifact_ref=job.manifest.ref,
                commitment=job.request.sealed,
                counts_by_criterion=counts_by_crit,
                evidence_hash=evidence_hash,
                judge_model=judge_model_used,
                signer=self.signer,
                clock=self.clock,
            )
            self.ledger.set_state(eval_key, LedgerState.SIGNED)

            # Step S12: Persist stored verdict atomically and return
            self.ledger.set_state(
                eval_key, LedgerState.STORED, verdict=signed_verdict
            )
            return EvaluationOutcome(
                status="verdict_issued",
                verdict=signed_verdict,
                audit_code="verdict_signed_and_stored",
            )

        except EvaluationAbortError as exc:
            if eval_key is not None and exc.code not in (
                AbortCode.EVALUATION_IN_PROGRESS,
                AbortCode.SEALED_SET_EXHAUSTED,
            ):
                try:
                    self.ledger.set_state(
                        eval_key, LedgerState.ABORTED, abort_code=exc.code
                    )
                except Exception:
                    pass
            return EvaluationOutcome(
                status="aborted",
                verdict=None,
                abort_code=exc.code,
                audit_code=exc.audit_detail,
            )
        except Exception as exc:
            if eval_key is not None:
                try:
                    self.ledger.set_state(
                        eval_key,
                        LedgerState.ABORTED,
                        abort_code=AbortCode.EVALUATION_INCOMPLETE,
                    )
                except Exception:
                    pass
            return EvaluationOutcome(
                status="aborted",
                verdict=None,
                abort_code=AbortCode.EVALUATION_INCOMPLETE,
                audit_code=RedactionLayer.sanitize_code_only(type(exc).__name__),
            )


# =========================================================================== #
# 9. LOCAL PERSISTENT VAULT ADAPTER & COMPREHENSIVE SELF-TEST SUITE
# =========================================================================== #


class SQLiteVaultAdapter:
    """Role-enforced persistent SQLite vault implementing VaultReaderPort."""

    def __init__(self, vault_db_path: Path) -> None:
        self.vault_db_path = Path(vault_db_path)
        self.vault_db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.vault_db_path, timeout=10.0) as conn:
            conn.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS eval_sealed_sets (
                    set_id TEXT PRIMARY KEY,
                    spec_hash TEXT NOT NULL,
                    commitment_hash TEXT NOT NULL,
                    commitment_json TEXT NOT NULL,
                    cases_json TEXT NOT NULL
                );
            """)

    def seal_normalized_cases(
        self,
        *,
        set_id: str,
        spec: Spec,
        cases: Sequence[SealedEvaluationCase],
    ) -> SealedSetCommitment:
        spec_hash = spec.content_hash()
        counts: dict[str, int] = {
            c.criterion_id: 0 for c in spec.acceptance_criteria
        }
        case_hashes: list[str] = []
        for tc in cases:
            full_h = tc.compute_case_hash()
            if tc.input_signature_hash != full_h:
                raise ValueError(
                    f"Cannot seal case '{tc.case_id}': input_signature_hash mismatch."
                )
            case_hashes.append(full_h)
            counts[tc.criterion_id] = counts.get(tc.criterion_id, 0) + 1

        c_hash = sha256_hex(
            _canonical_bytes(
                {
                    "set_id": set_id,
                    "spec_hash": spec_hash,
                    "counts": counts,
                    "case_hashes": case_hashes,
                }
            )
        )
        commitment = SealedSetCommitment(
            set_id=set_id,
            spec_hash=spec_hash,
            case_count=len(cases),
            criterion_case_counts=counts,
            commitment_hash=c_hash,
            sealed_at=datetime.now(timezone.utc),
        )
        with sqlite3.connect(self.vault_db_path, timeout=10.0) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO eval_sealed_sets
                (set_id, spec_hash, commitment_hash, commitment_json, cases_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    set_id,
                    spec_hash,
                    c_hash,
                    _canonical_bytes(commitment.model_dump(mode="json")).decode(
                        "utf-8"
                    ),
                    _canonical_bytes(
                        [c.model_dump(mode="json") for c in cases]
                    ).decode("utf-8"),
                ),
            )
        return commitment

    def open_sealed_set(
        self, set_id: str, *, caller_role: str = "eval"
    ) -> tuple[SealedSetCommitment, tuple[SealedEvaluationCase, ...]]:
        if caller_role != "eval":
            raise PermissionError(
                f"Vault access denied for caller_role='{caller_role}'; only 'eval' is permitted."
            )
        with sqlite3.connect(self.vault_db_path, timeout=10.0) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT commitment_json, cases_json FROM eval_sealed_sets WHERE set_id=?",
                (set_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Sealed set '{set_id}' not found.")
        commitment = SealedSetCommitment.model_validate(
            json.loads(row["commitment_json"])
        )
        cases = tuple(
            SealedEvaluationCase.model_validate(c)
            for c in json.loads(row["cases_json"])
        )
        return commitment, cases


def _make_eval_test_spec(include_rubric: bool = False) -> Spec:
    criteria = [
        AcceptanceCriterion(
            criterion_id="crit_decision",
            description="Exact match on refund decision.",
            method="exact_match",
            min_pass_rate=0.80,
        ),
        AcceptanceCriterion(
            criterion_id="crit_citation",
            description="Contains verbatim policy citation.",
            method="contains",
            min_pass_rate=0.80,
        ),
    ]
    if include_rubric:
        criteria.append(
            AcceptanceCriterion(
                criterion_id="crit_tone_rubric",
                description="Polite and compliant tone.",
                method="rubric",
                min_pass_rate=0.80,
            )
        )
    return Spec(
        goal="Evaluate customer refund requests and cite Section 4.2 policy.",
        inputs=[
            FieldSpec(
                name="query",
                data_type="string",
                description="Customer query",
                required=True,
            ),
            FieldSpec(
                name="days",
                data_type="integer",
                description="Days since purchase",
                required=True,
            ),
        ],
        outputs=[
            FieldSpec(
                name="decision",
                data_type="string",
                description="approve or reject",
                required=True,
            ),
            FieldSpec(
                name="policy_citation",
                data_type="string",
                description="Citation",
                required=True,
            ),
            FieldSpec(
                name="unrelated_note",
                data_type="string",
                description="Extra note",
                required=False,
            ),
        ],
        constraints=["Never approve refunds after 30 calendar days."],
        acceptance_criteria=criteria,
    )


def _make_sealed_cases_for_spec(
    spec: Spec, count_per_criterion: int = 18
) -> list[SealedEvaluationCase]:
    cases: list[SealedEvaluationCase] = []
    for crit in spec.acceptance_criteria:
        for i in range(count_per_criterion):
            inp = {
                "query": f"CONFIDENTIAL_HELD_OUT_QUERY_{crit.criterion_id}_{i}",
                "days": 10 if i % 2 == 0 else 45,
            }
            if crit.method == "exact_match":
                cases.append(
                    SealedEvaluationCase.model_validate(
                        {
                            "case_id": f"ho_{crit.criterion_id}_{i:02d}",
                            "criterion_id": crit.criterion_id,
                            "method": "exact_match",
                            "input_data": inp,
                            "target_fields": ("decision",),
                            "expected_output": {
                                "decision": "approve_refund"
                                if i % 2 == 0
                                else "reject_refund"
                            },
                        }
                    )
                )
            elif crit.method == "contains":
                cases.append(
                    SealedEvaluationCase.model_validate(
                        {
                            "case_id": f"ho_{crit.criterion_id}_{i:02d}",
                            "criterion_id": crit.criterion_id,
                            "method": "contains",
                            "input_data": inp,
                            "target_fields": ("policy_citation",),
                            "expected_output": {
                                "policy_citation": "30 calendar days"
                            },
                        }
                    )
                )
            elif crit.method == "rubric":
                cases.append(
                    SealedEvaluationCase.model_validate(
                        {
                            "case_id": f"ho_{crit.criterion_id}_{i:02d}",
                            "criterion_id": crit.criterion_id,
                            "method": "rubric",
                            "input_data": inp,
                            "target_fields": ("decision", "policy_citation"),
                            "expected_output": {},
                            "rubric_dimensions": (
                                {"id": "polite", "desc": "Polite tone"},
                            ),
                        }
                    )
                )
    return cases


def _make_test_bundle(
    spec: Spec,
    *,
    version_id: str = "v1.0.0-cand",
    architecture: Literal["prompt_only", "retrieval", "tool_use"] = "prompt_only",
    limits: RuntimeLimits | None = None,
    include_rag_steps: bool = False,
) -> tuple[BundleManifest, dict[str, bytes]]:
    io_schema = {
        "inputs": _spec_outputs_to_json_schema(spec.inputs),
        "outputs": _spec_outputs_to_json_schema(spec.outputs),
    }
    steps: list[PlanStep] = [
        PlanStep(
            step_id="s_in",
            component_ref="io.validate@1.0.0",
            config={"mode": "input"},
        )
    ]
    last_dep = "s_in"
    if include_rag_steps:
        steps.append(
            PlanStep(
                step_id="s_ingest",
                component_ref="doc.ingest@1.0.0",
                config={
                    "app_id": "eval-rag-app",
                    "chunk_size": 300,
                    "overlap": 30,
                    "formats": ["txt", "md"],
                },
                depends_on=(last_dep,),
            )
        )
        steps.append(
            PlanStep(
                step_id="s_ret",
                component_ref="retrieve.lexical@1.0.0",
                config={"app_id": "eval-rag-app", "top_k": 3, "mode": "any"},
                depends_on=("s_ingest",),
            )
        )
        last_dep = "s_ret"

    steps.extend(
        [
            PlanStep(
                step_id="s_prompt",
                component_ref="prompt.compose@1.0.0",
                config={
                    "template": "Goal: {goal}",
                    "verbatim_constraints": list(spec.constraints),
                    "max_context_tokens": 2000,
                },
                depends_on=(last_dep,),
            ),
            PlanStep(
                step_id="s_model",
                component_ref="model.chat@1.0.0",
                config={
                    "model": "muse-spark-1.3",
                    "effort": "low",
                    "max_tokens": 512,
                },
                depends_on=("s_prompt",),
            ),
            PlanStep(
                step_id="s_out",
                component_ref="output.structured@1.0.0",
                config={"json_schema": io_schema["outputs"]},
                depends_on=("s_model",),
            ),
        ]
    )
    app_cfg = {
        "spec_hash": spec.content_hash(),
        "goal": spec.goal,
        "constraints": list(spec.constraints),
        "steps": [s.model_dump(mode="json") for s in steps],
    }
    prompt_bytes = (
        "Goal: {goal}\n" + "\n".join(f"- {c}" for c in spec.constraints)
    ).encode("utf-8")
    files_data = {
        "app_config.json": _canonical_bytes(app_cfg),
        "schemas/io_schema.json": _canonical_bytes(io_schema),
        "prompts/system_prompt.txt": prompt_bytes,
    }
    af_list = tuple(
        ArtifactFile(path=p, sha256=sha256_hex(b), size_bytes=len(b))
        for p, b in sorted(files_data.items())
    )
    manifest = BundleManifest.seal(
        ArtifactContent(
            spec_hash=spec.content_hash(),
            architecture="retrieval" if include_rag_steps else architecture,
            runtime_model="muse-spark-1.3",
            reasoning_effort="low",
            entrypoint="app_config.json",
            files=af_list,
            allowed_tools=(),
            limits=limits or RuntimeLimits(),
        ),
        version_id=version_id,
        created_at=datetime.now(timezone.utc),
    )
    return manifest, files_data


class _ConfigurableEvalModelPort:
    def __init__(
        self,
        handler: Callable[..., dict[str, Any]],
    ) -> None:
        self.handler = handler
        self.calls = 0
        self.received_timeouts: list[float | None] = []

    def complete_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        output_schema: dict[str, Any],
        model_id: str,
        effort: str,
        max_tokens: int,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        self.calls += 1
        self.received_timeouts.append(timeout)
        sig = inspect.signature(self.handler)
        if len(sig.parameters) >= 2:
            return self.handler(user_prompt, timeout)
        return self.handler(user_prompt)


class EvaluatorSelfTestSuite(unittest.TestCase):
    """Comprehensive self-test suite verifying C1–C11, S1–S12, and all Timeout Fixes."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="adaptos_evaluator_test_")
        self.tmp_path = Path(self._tmp.name)
        self.eval_env = {"AGNOS_PROCESS_ROLE": "eval"}
        self.signer = Ed25519Signer(b"adaptos_protected_eval_seed_32b!")
        self.config = EvaluatorConfig(
            eval_db_path=self.tmp_path / "eval_plane.db",
            vault_db_path=self.tmp_path / "vault.db",
        )
        self.vault = SQLiteVaultAdapter(self.config.vault_db_path)

    def tearDown(self) -> None:
        # Checkpoint open SQLite WAL files so Windows releases locks before cleanup.
        import sqlite3 as _sqlite3
        for _db in Path(self._tmp.name).rglob("*.db"):
            try:
                with _sqlite3.connect(str(_db), timeout=2.0) as _c:
                    _c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except Exception:
                pass
        try:
            self._tmp.cleanup()
        except PermissionError:
            pass

    def test_01_boot_guard_blocks_wrong_role_and_factory_credentials(self) -> None:
        with self.assertRaises(EvaluationAbortError) as ctx_role:
            BootGuard.verify_startup(
                self.config, self.signer, env={"AGNOS_PROCESS_ROLE": "factory"}
            )
        self.assertEqual(ctx_role.exception.code, AbortCode.BOOT_GUARD_FAILED)

        with self.assertRaises(EvaluationAbortError) as ctx_cred:
            BootGuard.verify_startup(
                self.config,
                self.signer,
                env={"AGNOS_PROCESS_ROLE": "eval", "BUILDER_API_KEY": "secret123"},
            )
        self.assertEqual(ctx_cred.exception.code, AbortCode.BOOT_GUARD_FAILED)

        with self.assertRaises(PermissionError):
            self.vault.open_sealed_set("any_set", caller_role="builder")

    def test_02_strict_grader_target_field_isolation_and_seal_validation(self) -> None:
        spec = _make_eval_test_spec()
        grader = CaseGrader(spec=spec, runtime_model_id="muse-spark-1.3")

        contains_case = SealedEvaluationCase.model_validate(
            {
                "case_id": "c_cont_1",
                "criterion_id": "crit_citation",
                "method": "contains",
                "input_data": {"query": "q", "days": 5},
                "target_fields": ("policy_citation",),
                "expected_output": {"policy_citation": "30 calendar days"},
            }
        )
        wrong_field_exec = CaseExecutionOutcome(
            case_id="c_cont_1",
            status="ok",
            output={
                "decision": "approve_refund",
                "policy_citation": "No policy mentioned here.",
                "unrelated_note": "Full refunds within 30 calendar days.",
            },
            error_code="ok",
            latency_ms=5,
        )
        rec_wrong = grader.grade_case(contains_case, wrong_field_exec)
        self.assertEqual(rec_wrong.grade_status, "failed")

        exact_case = SealedEvaluationCase.model_validate(
            {
                "case_id": "c_ex_1",
                "criterion_id": "crit_decision",
                "method": "exact_match",
                "input_data": {"query": "q", "days": 5},
                "target_fields": ("decision",),
                "expected_output": {"decision": "approve_refund"},
            }
        )
        substring_exec = CaseExecutionOutcome(
            case_id="c_ex_1",
            status="ok",
            output={
                "decision": "approve_refund_with_extra_text",
                "policy_citation": "30 calendar days",
                "unrelated_note": "approve_refund",
            },
            error_code="ok",
            latency_ms=5,
        )
        self.assertEqual(
            grader.grade_case(exact_case, substring_exec).grade_status, "failed"
        )

        with self.assertRaises(ValueError):
            SealedEvaluationCase.model_validate(
                {
                    "case_id": "c_num_bad",
                    "criterion_id": "crit_decision",
                    "method": "numeric_tolerance",
                    "input_data": {"query": "q", "days": 5},
                    "target_fields": ("decision",),
                    "expected_output": {"decision": "not_a_number"},
                }
            )

    def test_03_s1_to_s12_ready_verdict_idempotency_and_one_shot_set_budget(self) -> None:
        spec = _make_eval_test_spec()
        cases = _make_sealed_cases_for_spec(spec, count_per_criterion=18)
        commitment = self.vault.seal_normalized_cases(
            set_id="sealed_set_ready_01", spec=spec, cases=cases
        )
        manifest, files_data = _make_test_bundle(spec, version_id="v1.0.0-cand")

        def _perfect_model(prompt: str) -> dict[str, Any]:
            decision = "approve_refund" if '"days":10' in prompt else "reject_refund"
            return {
                "decision": decision,
                "policy_citation": "Full refunds are granted within 30 calendar days of purchase.",
                "unrelated_note": "ok",
            }

        model_port = _ConfigurableEvalModelPort(_perfect_model)
        coord = EvaluatorCoordinator(
            config=self.config,
            vault_port=self.vault,
            runtime_model_port=model_port,
            signer=self.signer,
            env_override=self.eval_env,
        )
        job = EvaluationJob(
            request_id="req_001",
            request=EvaluationRequest(
                artifact=manifest, spec=spec, sealed=commitment
            ),
            spec=spec,
            manifest=manifest,
            files_data=files_data,
        )

        out1 = coord.evaluate_job(job)
        self.assertEqual(out1.status, "verdict_issued")
        assert out1.verdict is not None
        self.assertEqual(out1.verdict.status, "ready")
        self.assertEqual(out1.verdict.signing_key_id, self.signer.key_id)
        self.assertTrue(
            Ed25519Signer.verify_signature(
                self.signer.public_key_bytes,
                out1.verdict.signing_payload(),
                out1.verdict.signature,
            )
        )
        calls_after_first = model_port.calls
        self.assertEqual(calls_after_first, 36)

        out2 = coord.evaluate_job(job)
        self.assertEqual(out2.status, "verdict_issued")
        assert out2.verdict is not None
        self.assertEqual(out2.verdict.verdict_id, out1.verdict.verdict_id)
        self.assertEqual(model_port.calls, calls_after_first)

        manifest_v2, files_v2 = _make_test_bundle(spec, version_id="v2.0.0-cand")
        files_v2["prompts/system_prompt.txt"] += b"\n# v2"
        af_v2 = tuple(
            ArtifactFile(path=p, sha256=sha256_hex(b), size_bytes=len(b))
            for p, b in sorted(files_v2.items())
        )
        manifest_v2 = BundleManifest.seal(
            ArtifactContent(
                spec_hash=spec.content_hash(),
                architecture="prompt_only",
                runtime_model="muse-spark-1.3",
                reasoning_effort="low",
                entrypoint="app_config.json",
                files=af_v2,
                allowed_tools=(),
                limits=RuntimeLimits(),
            ),
            version_id="v2.0.0-cand",
            created_at=datetime.now(timezone.utc),
        )
        job_v2 = EvaluationJob(
            request_id="req_002",
            request=EvaluationRequest(
                artifact=manifest_v2, spec=spec, sealed=commitment
            ),
            spec=spec,
            manifest=manifest_v2,
            files_data=files_v2,
        )
        out_exhausted = coord.evaluate_job(job_v2)
        self.assertEqual(out_exhausted.status, "aborted")
        self.assertEqual(out_exhausted.abort_code, AbortCode.SEALED_SET_EXHAUSTED)

    def test_04_rubric_without_judge_yields_insufficient_evidence(self) -> None:
        spec = _make_eval_test_spec(include_rubric=True)
        cases = _make_sealed_cases_for_spec(spec, count_per_criterion=18)
        commitment = self.vault.seal_normalized_cases(
            set_id="sealed_rubric_01", spec=spec, cases=cases
        )
        manifest, files_data = _make_test_bundle(spec, version_id="v1-rubric")

        model_port = _ConfigurableEvalModelPort(
            lambda p: {
                "decision": "approve_refund" if '"days":10' in p else "reject_refund",
                "policy_citation": "30 calendar days",
                "unrelated_note": "ok",
            }
        )
        coord = EvaluatorCoordinator(
            config=self.config,
            vault_port=self.vault,
            runtime_model_port=model_port,
            signer=self.signer,
            judge_port=None,
            env_override=self.eval_env,
        )
        out = coord.evaluate_job(
            EvaluationJob(
                request_id="req_rub_1",
                request=EvaluationRequest(
                    artifact=manifest, spec=spec, sealed=commitment
                ),
                spec=spec,
                manifest=manifest,
                files_data=files_data,
            )
        )
        self.assertEqual(out.status, "verdict_issued")
        assert out.verdict is not None
        self.assertIn(out.verdict.status, ("insufficient_evidence", "insufficient"))

    def test_05_infra_error_aborts_without_not_ready_and_crash_recovery_resumes(self) -> None:
        spec = _make_eval_test_spec()
        cases = _make_sealed_cases_for_spec(spec, count_per_criterion=18)
        commitment = self.vault.seal_normalized_cases(
            set_id="sealed_crash_01", spec=spec, cases=cases
        )
        manifest, files_data = _make_test_bundle(spec, version_id="v1-crash")

        call_num = 0

        def _flaky_infra_model(prompt: str) -> dict[str, Any]:
            nonlocal call_num
            call_num += 1
            if call_num > 10:
                raise InfrastructureModelError("Provider 503 Service Unavailable")
            return {
                "decision": "approve_refund" if '"days":10' in prompt else "reject_refund",
                "policy_citation": "30 calendar days",
                "unrelated_note": "ok",
            }

        resumable_cfg = EvaluatorConfig(
            eval_db_path=self.config.eval_db_path,
            vault_db_path=self.config.vault_db_path,
            max_infra_retries=0,
            allow_resumable_incomplete=True,
        )
        coord1 = EvaluatorCoordinator(
            config=resumable_cfg,
            vault_port=self.vault,
            runtime_model_port=_ConfigurableEvalModelPort(_flaky_infra_model),
            signer=self.signer,
            env_override=self.eval_env,
        )
        job = EvaluationJob(
            request_id="req_crash_1",
            request=EvaluationRequest(
                artifact=manifest, spec=spec, sealed=commitment
            ),
            spec=spec,
            manifest=manifest,
            files_data=files_data,
        )

        out_incomplete = coord1.evaluate_job(job)
        self.assertEqual(out_incomplete.status, "aborted")
        self.assertIsNone(out_incomplete.verdict)
        self.assertEqual(
            out_incomplete.abort_code, AbortCode.EVALUATION_INCOMPLETE
        )

        healthy_port = _ConfigurableEvalModelPort(
            lambda p: {
                "decision": "approve_refund" if '"days":10' in p else "reject_refund",
                "policy_citation": "30 calendar days",
                "unrelated_note": "ok",
            }
        )
        coord2 = EvaluatorCoordinator(
            config=resumable_cfg,
            vault_port=self.vault,
            runtime_model_port=healthy_port,
            signer=self.signer,
            env_override=self.eval_env,
        )
        out_resumed = coord2.evaluate_job(job)
        self.assertEqual(out_resumed.status, "verdict_issued")
        assert out_resumed.verdict is not None
        self.assertEqual(out_resumed.verdict.status, "ready")
        self.assertEqual(healthy_port.calls, 26)

    def test_06_tampered_artifact_and_redaction_guarantees(self) -> None:
        spec = _make_eval_test_spec()
        cases = _make_sealed_cases_for_spec(spec, count_per_criterion=18)
        commitment = self.vault.seal_normalized_cases(
            set_id="sealed_tamper_01", spec=spec, cases=cases
        )
        manifest, files_data = _make_test_bundle(spec, version_id="v1-tamper")

        tampered_files = {
            **files_data,
            "prompts/system_prompt.txt": b"TAMPERED_BYTES",
        }
        coord = EvaluatorCoordinator(
            config=self.config,
            vault_port=self.vault,
            runtime_model_port=_ConfigurableEvalModelPort(lambda p: {}),
            signer=self.signer,
            env_override=self.eval_env,
        )
        out = coord.evaluate_job(
            EvaluationJob(
                request_id="req_tamper",
                request=EvaluationRequest(
                    artifact=manifest, spec=spec, sealed=commitment
                ),
                spec=spec,
                manifest=manifest,
                files_data=tampered_files,
            )
        )
        self.assertEqual(out.status, "aborted")
        self.assertIsNone(out.verdict)
        self.assertEqual(out.abort_code, AbortCode.ARTIFACT_INTEGRITY_FAILED)

        serialized = json.dumps(out.model_dump(mode="json"))
        self.assertNotIn("CONFIDENTIAL_HELD_OUT_QUERY", serialized)

    def test_07_full_sealed_case_cryptographic_binding_and_tampering_detection(self) -> None:
        spec = _make_eval_test_spec()
        cases = _make_sealed_cases_for_spec(spec, count_per_criterion=18)
        commitment = self.vault.seal_normalized_cases(
            set_id="sealed_full_bind_01", spec=spec, cases=cases
        )
        reader = SealedSetReader(self.vault)

        verified_cases = reader.read_and_verify(
            expected_commitment=commitment, spec=spec
        )
        self.assertEqual(len(verified_cases), 36)

        def _assert_tamper_rejected(mutator: Callable[[dict[str, Any]], None]) -> None:
            with sqlite3.connect(self.config.vault_db_path) as conn:
                orig_json = conn.execute(
                    "SELECT cases_json FROM eval_sealed_sets WHERE set_id='sealed_full_bind_01'"
                ).fetchone()[0]
            try:
                raw_list = json.loads(orig_json)
                mutator(raw_list[0])
                with sqlite3.connect(self.config.vault_db_path) as conn:
                    conn.execute(
                        "UPDATE eval_sealed_sets SET cases_json=? WHERE set_id='sealed_full_bind_01'",
                        (json.dumps(raw_list),),
                    )
                with self.assertRaises(EvaluationAbortError) as ctx:
                    reader.read_and_verify(expected_commitment=commitment, spec=spec)
                self.assertEqual(ctx.exception.code, AbortCode.SEALED_SET_INVALID)
            finally:
                with sqlite3.connect(self.config.vault_db_path) as conn:
                    conn.execute(
                        "UPDATE eval_sealed_sets SET cases_json=? WHERE set_id='sealed_full_bind_01'",
                        (orig_json,),
                    )

        _assert_tamper_rejected(
            lambda c: c.update({"expected_output": {"decision": "reject_refund"}})
        )

        def _tamper_expected_and_rehash(c: dict[str, Any]) -> None:
            c["expected_output"] = {"decision": "reject_refund"}
            c["input_signature_hash"] = compute_sealed_case_hash(
                case_id=c["case_id"],
                criterion_id=c["criterion_id"],
                method=c["method"],
                input_data=c["input_data"],
                target_fields=c["target_fields"],
                expected_output=c["expected_output"],
                numeric_tolerance=c["numeric_tolerance"],
                rubric_dimensions=c["rubric_dimensions"],
            )

        _assert_tamper_rejected(_tamper_expected_and_rehash)
        _assert_tamper_rejected(
            lambda c: c.update(
                {
                    "target_fields": ["policy_citation"],
                    "expected_output": {"policy_citation": "x"},
                }
            )
        )
        _assert_tamper_rejected(lambda c: c.update({"numeric_tolerance": 0.5}))
        _assert_tamper_rejected(lambda c: c.update({"case_id": "ho_tampered_id"}))

    def test_08_preemptive_per_case_execution_deadline_including_external_model_calls(self) -> None:
        """Required Test 1: A runtime call that exceeds the deadline produces a timeout result."""
        spec = _make_eval_test_spec()
        manifest, files_data = _make_test_bundle(
            spec,
            version_id="v1-timeout",
            limits=RuntimeLimits(wall_seconds=1, memory_mb=256),
        )

        def _slow_model_call(prompt: str, timeout: float | None = None) -> dict[str, Any]:
            time.sleep(2.5)
            return {
                "decision": "approve_refund",
                "policy_citation": "30 calendar days",
                "unrelated_note": "ok",
            }

        env = EnvironmentFactory.create(
            manifest=manifest,
            files_data=files_data,
            model_port=_ConfigurableEvalModelPort(_slow_model_call),
            config=self.config,
        )
        try:
            executor = CaseExecutor(self.config)
            t0 = time.monotonic()
            outcome = executor.execute_case(
                env=env,
                manifest=manifest,
                files_data=files_data,
                input_data={"query": "test timeout", "days": 10},
                case_id="c_timeout_01",
                assets=(),
            )
            elapsed = time.monotonic() - t0
            self.assertEqual(outcome.status, "artifact_error")
            self.assertEqual(outcome.error_code, "case_wall_timeout_exceeded")
            self.assertLess(elapsed, 1.8)
        finally:
            env.cleanup()

    def test_09_cross_case_storage_isolation_prevents_state_contamination(self) -> None:
        spec = _make_eval_test_spec()
        manifest, files_data = _make_test_bundle(
            spec, version_id="v1-rag-iso", include_rag_steps=True
        )
        seen_prompts: list[str] = []

        def _capturing_model(prompt: str) -> dict[str, Any]:
            seen_prompts.append(prompt)
            return {
                "decision": "approve_refund",
                "policy_citation": "30 calendar days",
                "unrelated_note": "ok",
            }

        env = EnvironmentFactory.create(
            manifest=manifest,
            files_data=files_data,
            model_port=_ConfigurableEvalModelPort(_capturing_model),
            config=self.config,
        )
        try:
            executor = CaseExecutor(self.config)
            out1 = executor.execute_case(
                env=env,
                manifest=manifest,
                files_data=files_data,
                input_data={"query": "CASE1_CONTAMINATION_MARKER_TOKEN", "days": 10},
                case_id="case_1",
                assets=(
                    SourceAssetInput(
                        asset_id="a1",
                        filename="doc1.txt",
                        content="CASE1_CONTAMINATION_MARKER_TOKEN is present in case 1.",
                        format="txt",
                    ),
                ),
            )
            self.assertEqual(out1.status, "ok")
            self.assertIn("CASE1_CONTAMINATION_MARKER_TOKEN", seen_prompts[0])

            out2 = executor.execute_case(
                env=env,
                manifest=manifest,
                files_data=files_data,
                input_data={"query": "CASE1_CONTAMINATION_MARKER_TOKEN", "days": 10},
                case_id="case_2",
                assets=(),
            )
            self.assertEqual(out2.status, "ok")
            self.assertNotIn(
                "CASE1_CONTAMINATION_MARKER_TOKEN is present in case 1.",
                seen_prompts[1],
            )
        finally:
            env.cleanup()

    def test_10_atomic_sealed_set_budget_reservation_blocks_concurrent_evaluations(self) -> None:
        ledger = EvaluationLedger(self.config.eval_db_path, max_evaluations_per_set=1)

        cached_a = ledger.check_s2_gate_and_begin(
            artifact_hash="a" * 64,
            spec_hash="s" * 64,
            sealed_set_id="sealed_atomic_set_01",
        )
        self.assertIsNone(cached_a)

        with self.assertRaises(EvaluationAbortError) as ctx_dup:
            ledger.check_s2_gate_and_begin(
                artifact_hash="a" * 64,
                spec_hash="s" * 64,
                sealed_set_id="sealed_atomic_set_01",
            )
        self.assertEqual(ctx_dup.exception.code, AbortCode.EVALUATION_IN_PROGRESS)

        with self.assertRaises(EvaluationAbortError) as ctx_b:
            ledger.check_s2_gate_and_begin(
                artifact_hash="b" * 64,
                spec_hash="s" * 64,
                sealed_set_id="sealed_atomic_set_01",
            )
        self.assertEqual(ctx_b.exception.code, AbortCode.SEALED_SET_EXHAUSTED)

    def test_11_judge_model_identity_and_rubric_dimension_validation(self) -> None:
        spec = _make_eval_test_spec(include_rubric=True)
        rubric_case = SealedEvaluationCase.model_validate(
            {
                "case_id": "ho_rub_01",
                "criterion_id": "crit_tone_rubric",
                "method": "rubric",
                "input_data": {"query": "Refund please", "days": 5},
                "target_fields": ("decision", "policy_citation"),
                "expected_output": {},
                "rubric_dimensions": (
                    {"id": "polite", "desc": "Polite tone"},
                    {"id": "accurate", "desc": "Accurate policy reference"},
                ),
            }
        )
        exec_ok = CaseExecutionOutcome(
            case_id="ho_rub_01",
            status="ok",
            output={
                "decision": "approve_refund",
                "policy_citation": "30 calendar days",
                "unrelated_note": "ok",
            },
            error_code="ok",
            latency_ms=10,
        )

        class _MockJudge:
            def __init__(self, model_id: str, verdict: JudgeVerdict) -> None:
                self._model_id = model_id
                self._verdict = verdict

            @property
            def judge_model_id(self) -> str:
                return self._model_id

            def evaluate_rubric(self, **kwargs: Any) -> JudgeVerdict:
                return self._verdict

        same_model_grader = CaseGrader(
            spec=spec,
            runtime_model_id="muse-spark-1.3",
            judge_port=_MockJudge(
                "muse-spark-1.3",
                JudgeVerdict(
                    passed=True,
                    dimension_scores={"polite": 1, "accurate": 1},
                    judge_model="muse-spark-1.3",
                ),
            ),
        )
        rec_same = same_model_grader.grade_case(rubric_case, exec_ok)
        self.assertEqual(rec_same.grade_status, "ungraded")
        self.assertEqual(rec_same.error_code, "judge_same_as_runtime_model")

        missing_dim_grader = CaseGrader(
            spec=spec,
            runtime_model_id="muse-spark-1.3",
            judge_port=_MockJudge(
                "muse-wonder-1.0",
                JudgeVerdict(
                    passed=True,
                    dimension_scores={"polite": 1},
                    judge_model="muse-wonder-1.0",
                ),
            ),
        )
        rec_missing = missing_dim_grader.grade_case(rubric_case, exec_ok)
        self.assertEqual(rec_missing.grade_status, "ungraded")
        self.assertEqual(rec_missing.error_code, "judge_invalid_dimension_scores")

        disagree_grader = CaseGrader(
            spec=spec,
            runtime_model_id="muse-spark-1.3",
            judge_port=_MockJudge(
                "muse-wonder-1.0",
                JudgeVerdict(
                    passed=True,
                    dimension_scores={"polite": 1, "accurate": 0},
                    judge_model="muse-wonder-1.0",
                ),
            ),
        )
        rec_disagree = disagree_grader.grade_case(rubric_case, exec_ok)
        self.assertEqual(rec_disagree.grade_status, "ungraded")
        self.assertEqual(rec_disagree.error_code, "judge_dimension_pass_disagreement")

        valid_grader = CaseGrader(
            spec=spec,
            runtime_model_id="muse-spark-1.3",
            judge_port=_MockJudge(
                "muse-wonder-1.0",
                JudgeVerdict(
                    passed=True,
                    dimension_scores={"polite": 1, "accurate": 1},
                    judge_model="muse-wonder-1.0",
                ),
            ),
        )
        rec_valid = valid_grader.grade_case(rubric_case, exec_ok)
        self.assertEqual(rec_valid.grade_status, "passed")
        self.assertEqual(rec_valid.judge_model, "muse-wonder-1.0")

    def test_12_crash_recovery_validates_persisted_grade_records_against_sealed_cases(self) -> None:
        spec = _make_eval_test_spec()
        cases = _make_sealed_cases_for_spec(spec, count_per_criterion=18)
        ledger = EvaluationLedger(self.config.eval_db_path)
        eval_key = ledger.make_eval_key("art123", spec.content_hash(), "set_rec_01")

        tc0 = cases[0]
        valid_rec = CaseGradeRecord(
            case_id=tc0.case_id,
            criterion_id=tc0.criterion_id,
            method=tc0.method,
            grade_status="passed",
            error_code="ok",
            latency_ms=12,
            case_hash=tc0.compute_case_hash(),
            grader_version=GRADER_VERSION,
        )
        ledger.save_case_grade(eval_key, valid_rec)

        loaded = ledger.load_validated_case_grades(
            eval_key=eval_key,
            sealed_cases=cases,
            runtime_model_id="muse-spark-1.3",
        )
        self.assertIn(tc0.case_id, loaded)

        with sqlite3.connect(self.config.eval_db_path) as conn:
            conn.execute(
                "UPDATE eval_case_progress SET case_hash=? WHERE eval_key=? AND case_id=?",
                ("f" * 64, eval_key, tc0.case_id),
            )

        with self.assertRaises(EvaluationAbortError) as ctx_tamper:
            ledger.load_validated_case_grades(
                eval_key=eval_key,
                sealed_cases=cases,
                runtime_model_id="muse-spark-1.3",
            )
        self.assertEqual(
            ctx_tamper.exception.code, AbortCode.EVIDENCE_STORE_UNAVAILABLE
        )

    def test_13_retry_cannot_extend_original_case_deadline_and_fast_retry_succeeds(self) -> None:
        """Required Tests 2 & 6: Proves retries share the original case deadline (never resetting
        wall_seconds on retry), while fast retries that finish within the deadline still succeed.
        """
        spec = _make_eval_test_spec()
        manifest, files_data = _make_test_bundle(
            spec,
            version_id="v1-retry-deadline",
            limits=RuntimeLimits(wall_seconds=1, memory_mb=256),
        )
        retry_cfg = EvaluatorConfig(
            eval_db_path=self.config.eval_db_path,
            vault_db_path=self.config.vault_db_path,
            max_infra_retries=3,
            infra_retry_delay_seconds=0.01,
        )

        # 13a. Slow retries: Attempt 1 takes 0.6s and fails with InfrastructureModelError;
        # Attempt 2 tries to take 0.6s (which would total 1.2s > 1.0s wall_seconds).
        # The single case deadline MUST cut off Attempt 2 at ~1.0s total elapsed time!
        slow_attempts = 0

        def _slow_failing_retry_model(prompt: str, timeout: float | None = None) -> dict[str, Any]:
            nonlocal slow_attempts
            slow_attempts += 1
            time.sleep(0.6)
            if slow_attempts == 1:
                raise InfrastructureModelError("Transient 503 on attempt 1")
            return {
                "decision": "approve_refund",
                "policy_citation": "30 calendar days",
                "unrelated_note": "ok",
            }

        env1 = EnvironmentFactory.create(
            manifest=manifest,
            files_data=files_data,
            model_port=_ConfigurableEvalModelPort(_slow_failing_retry_model),
            config=retry_cfg,
        )
        try:
            executor = CaseExecutor(retry_cfg)
            t0 = time.monotonic()
            out_timeout = executor.execute_case(
                env=env1,
                manifest=manifest,
                files_data=files_data,
                input_data={"query": "retry deadline test", "days": 10},
                case_id="c_retry_timeout",
                assets=(),
            )
            elapsed = time.monotonic() - t0
            self.assertEqual(out_timeout.status, "artifact_error")
            self.assertEqual(out_timeout.error_code, "case_wall_timeout_exceeded")
            # Total time across both attempts was capped at the original 1.0s deadline!
            self.assertLess(elapsed, 1.35)
            self.assertEqual(slow_attempts, 2)
        finally:
            env1.cleanup()

        # 13b. Fast transient retry within the 1.0s deadline still succeeds (Required Test 6)
        fast_attempts = 0

        def _fast_recovering_model(prompt: str, timeout: float | None = None) -> dict[str, Any]:
            nonlocal fast_attempts
            fast_attempts += 1
            if fast_attempts == 1:
                raise InfrastructureModelError("Transient 429 on attempt 1")
            return {
                "decision": "approve_refund",
                "policy_citation": "30 calendar days",
                "unrelated_note": "ok",
            }

        env2 = EnvironmentFactory.create(
            manifest=manifest,
            files_data=files_data,
            model_port=_ConfigurableEvalModelPort(_fast_recovering_model),
            config=retry_cfg,
        )
        try:
            out_ok = CaseExecutor(retry_cfg).execute_case(
                env=env2,
                manifest=manifest,
                files_data=files_data,
                input_data={"query": "fast retry test", "days": 10},
                case_id="c_retry_ok",
                assets=(),
            )
            self.assertEqual(out_ok.status, "ok")
            self.assertEqual(fast_attempts, 2)
        finally:
            env2.cleanup()

    def test_14_model_request_receives_remaining_timeout_budget(self) -> None:
        """Required Test 3: Proves each model call receives the remaining timeout budget from
        the single case deadline, and that a retry receives a smaller remaining timeout budget.
        """
        spec = _make_eval_test_spec()
        manifest, files_data = _make_test_bundle(
            spec,
            version_id="v1-budget-pass",
            limits=RuntimeLimits(wall_seconds=1, memory_mb=256),
        )
        call_idx = 0

        def _budget_inspecting_model(
            prompt: str, timeout: float | None = None
        ) -> dict[str, Any]:
            nonlocal call_idx
            call_idx += 1
            if call_idx == 1:
                time.sleep(0.25)
                raise InfrastructureModelError("Retry after 0.25s")
            return {
                "decision": "approve_refund",
                "policy_citation": "30 calendar days",
                "unrelated_note": "ok",
            }

        port = _ConfigurableEvalModelPort(_budget_inspecting_model)
        env = EnvironmentFactory.create(
            manifest=manifest,
            files_data=files_data,
            model_port=port,
            config=self.config,
        )
        try:
            out = CaseExecutor(self.config).execute_case(
                env=env,
                manifest=manifest,
                files_data=files_data,
                input_data={"query": "budget check", "days": 10},
                case_id="c_budget_1",
                assets=(),
            )
            self.assertEqual(out.status, "ok")
            self.assertEqual(len(port.received_timeouts), 2)
            t1, t2 = port.received_timeouts[0], port.received_timeouts[1]
            assert t1 is not None and t2 is not None
            self.assertGreater(t1, 0.70)
            self.assertLessEqual(t1, 1.0)
            # Second call (on retry after 0.25s + backoff) received a strictly smaller timeout budget!
            self.assertLess(t2, t1 - 0.20)
            self.assertGreater(t2, 0.0)
        finally:
            env.cleanup()

    def test_15_timed_out_execution_cannot_contaminate_next_case_storage_or_credits(self) -> None:
        """Required Test 4: Proves a timed-out execution that continues running in the background
        cannot mutate or contaminate the next case's storage or consume additional API credits.
        """
        spec = _make_eval_test_spec()
        manifest, files_data = _make_test_bundle(
            spec,
            version_id="v1-zombie-guard",
            limits=RuntimeLimits(wall_seconds=1, memory_mb=256),
            include_rag_steps=True,
        )

        zombie_late_storage_error: list[str] = []
        zombie_late_model_error: list[str] = []
        case2_prompts: list[str] = []
        captured_case1_runtime: list[AppRuntime] = []

        def _zombie_vs_case2_model(
            prompt: str, timeout: float | None = None
        ) -> dict[str, Any]:
            if "CASE_1_SLOW_ZOMBIE" in prompt:
                # Capture the AppRuntime used by Case 1
                rt_ref = env.runtime
                captured_case1_runtime.append(rt_ref)
                # Sleep past the 1.0s case timeout so Case 1 returns timeout
                time.sleep(1.25)
                # Now Case 1 has already timed out! Try to write a poisoned document to Case 1's
                # storage and make a second unauthorized model call:
                try:
                    rt_ref.storage.add_fts5_document(
                        "eval-rag-app",
                        "poison_doc",
                        "POISONED_ZOMBIE_TOKEN_999 FROM TIMED OUT CASE 1",
                    )
                except Exception as exc_st:
                    zombie_late_storage_error.append(type(exc_st).__name__)
                try:
                    rt_ref.model_port.complete_json(
                        system_prompt="s",
                        user_prompt="late call",
                        output_schema={},
                        model_id="muse-spark-1.3",
                        effort="low",
                        max_tokens=10,
                    )
                except Exception as exc_mod:
                    zombie_late_model_error.append(type(exc_mod).__name__)
                return {
                    "decision": "approve_refund",
                    "policy_citation": "30 calendar days",
                    "unrelated_note": "ok",
                }

            # Case 2 execution
            case2_prompts.append(prompt)
            return {
                "decision": "approve_refund",
                "policy_citation": "30 calendar days",
                "unrelated_note": "ok",
            }

        port = _ConfigurableEvalModelPort(_zombie_vs_case2_model)
        env = EnvironmentFactory.create(
            manifest=manifest,
            files_data=files_data,
            model_port=port,
            config=self.config,
        )
        try:
            executor = CaseExecutor(self.config)
            # 1. Run Case 1 -> times out at 1.0s while zombie thread sleeps until 1.25s
            out1 = executor.execute_case(
                env=env,
                manifest=manifest,
                files_data=files_data,
                input_data={
                    "query": "CASE_1_SLOW_ZOMBIE POISONED_ZOMBIE_TOKEN_999",
                    "days": 10,
                },
                case_id="case_1_zombie",
                assets=(
                    SourceAssetInput(
                        asset_id="a1",
                        filename="d1.txt",
                        content="Initial doc for case 1.",
                        format="txt",
                    ),
                ),
            )
            self.assertEqual(out1.status, "artifact_error")
            self.assertEqual(out1.error_code, "case_wall_timeout_exceeded")

            # Wait 0.35s so the zombie thread wakes up at 1.25s and attempts its late writes
            time.sleep(0.35)
            self.assertEqual(zombie_late_storage_error, ["CaseDeadlineExceededError"])
            self.assertEqual(zombie_late_model_error, ["CaseDeadlineExceededError"])
            # Zombie thread's late model call was blocked BEFORE charging spent_usd or calling inner port!
            self.assertEqual(port.calls, 1)

            # 2. Run Case 2 searching for POISONED_ZOMBIE_TOKEN_999 -> isolated storage has 0 contamination!
            out2 = executor.execute_case(
                env=env,
                manifest=manifest,
                files_data=files_data,
                input_data={"query": "POISONED_ZOMBIE_TOKEN_999", "days": 10},
                case_id="case_2_clean",
                assets=(
                    SourceAssetInput(
                        asset_id="a2",
                        filename="d2.txt",
                        content="Clean passage within 30 calendar days.",
                        format="txt",
                    ),
                ),
            )
            self.assertEqual(out2.status, "ok")
            self.assertEqual(len(case2_prompts), 1)
            self.assertNotIn(
                "FROM TIMED OUT CASE 1", case2_prompts[0]
            )
        finally:
            env.cleanup()

    def test_16_timeout_cannot_produce_passing_grade_or_ready_verdict(self) -> None:
        """Required Test 5: Proves that timed-out executions are deterministically graded as failed
        and can never produce a passing grade or a ready Verdict.
        """
        spec = Spec(
            goal="Single criterion timeout verdict check.",
            inputs=[
                FieldSpec(
                    name="query", data_type="string", description="q", required=True
                ),
                FieldSpec(
                    name="days", data_type="integer", description="d", required=True
                ),
            ],
            outputs=[
                FieldSpec(
                    name="decision", data_type="string", description="out", required=True
                ),
            ],
            constraints=["Never approve refunds after 30 calendar days."],
            acceptance_criteria=[
                AcceptanceCriterion(
                    criterion_id="crit_only",
                    description="Exact match decision.",
                    method="exact_match",
                    min_pass_rate=0.50,  # required_cases(0.50) == 5 cases
                )
            ],
        )
        cases = _make_sealed_cases_for_spec(spec, count_per_criterion=5)
        commitment = self.vault.seal_normalized_cases(
            set_id="sealed_timeout_verdict_01", spec=spec, cases=cases
        )
        manifest, files_data = _make_test_bundle(
            spec,
            version_id="v1-timeout-verdict",
            limits=RuntimeLimits(wall_seconds=1, memory_mb=256),
        )

        def _always_timeout_model(
            prompt: str, timeout: float | None = None
        ) -> dict[str, Any]:
            time.sleep(1.5)
            return {"decision": "approve_refund"}

        coord = EvaluatorCoordinator(
            config=self.config,
            vault_port=self.vault,
            runtime_model_port=_ConfigurableEvalModelPort(_always_timeout_model),
            signer=self.signer,
            env_override=self.eval_env,
        )
        outcome = coord.evaluate_job(
            EvaluationJob(
                request_id="req_timeout_verdict",
                request=EvaluationRequest(
                    artifact=manifest, spec=spec, sealed=commitment
                ),
                spec=spec,
                manifest=manifest,
                files_data=files_data,
            )
        )
        self.assertEqual(outcome.status, "verdict_issued")
        assert outcome.verdict is not None
        self.assertEqual(outcome.verdict.status, "not_ready")
        self.assertEqual(outcome.verdict.criteria[0].n_passed, 0)
        self.assertEqual(outcome.verdict.criteria[0].n_cases, 5)
        self.assertFalse(outcome.verdict.criteria[0].passed)


def _run_demo() -> int:
    with tempfile.TemporaryDirectory(prefix="adaptos_evaluator_demo_") as tmp:
        tmp_p = Path(tmp)
        signer = Ed25519Signer(b"adaptos_protected_eval_seed_32b!")
        cfg = EvaluatorConfig(
            eval_db_path=tmp_p / "eval_plane.db",
            vault_db_path=tmp_p / "vault.db",
        )
        vault = SQLiteVaultAdapter(cfg.vault_db_path)
        spec = _make_eval_test_spec()
        cases = _make_sealed_cases_for_spec(spec, count_per_criterion=18)
        commitment = vault.seal_normalized_cases(
            set_id="demo_sealed_set_01", spec=spec, cases=cases
        )
        manifest, files_data = _make_test_bundle(spec, version_id="v1.0.0-candidate")
        model_port = _ConfigurableEvalModelPort(
            lambda p, timeout=None: {
                "decision": "approve_refund" if '"days":10' in p else "reject_refund",
                "policy_citation": "Full refunds are granted within 30 calendar days of purchase.",
                "unrelated_note": "ok",
            }
        )
        coord = EvaluatorCoordinator(
            config=cfg,
            vault_port=vault,
            runtime_model_port=model_port,
            signer=signer,
            env_override={"AGNOS_PROCESS_ROLE": "eval"},
        )
        outcome = coord.evaluate_job(
            EvaluationJob(
                request_id="demo_req_01",
                request=EvaluationRequest(
                    artifact=manifest, spec=spec, sealed=commitment
                ),
                spec=spec,
                manifest=manifest,
                files_data=files_data,
            )
        )
        print(
            json.dumps(
                {
                    "outcome_status": outcome.status,
                    "audit_code": outcome.audit_code,
                    "verdict": outcome.verdict.model_dump(mode="json")
                    if outcome.verdict
                    else None,
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="AdaptOS Protected Evaluation Plane Coordinator"
    )
    parser.add_argument(
        "--self-test", action="store_true", help="Run built-in Evaluator unittest suite"
    )
    parser.add_argument(
        "--demo", action="store_true", help="Run Protected Evaluator demo"
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.demo:
        return _run_demo()

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(EvaluatorSelfTestSuite)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())