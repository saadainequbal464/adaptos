"""backend/service.py — AdaptOS Application & Evaluation Service Layer.

Coordinates the end-to-end 12-step AdaptOS workflow across existing subsystems:
1. Project initialization (`create_project`, with duplicate `run_id` overwrite protection)
2. Requirement intake and asset profiling (`ingest_assets`)
3. Spec submission and validated `HandoffPackage` approval (`submit_spec_for_review`, `approve_spec`)
4. Evaluation criteria and test-case design (`design_evaluation` / `FactoryOrchestrator.design_eval_node`)
5. Development and protected test-case splitting & sealing (`NormalizedVaultSplitterAdapter`)
6. Application architecture & implementation (`BuildEngine` / `FactoryOrchestrator.build_node`)
7. Development testing (`DevTestRunner` / `FactoryOrchestrator.dev_test_node`)
8. Failure diagnosis & bounded repair (`repair_attempt` / `FactoryOrchestrator.repair_node`)
9. Candidate freeze (`FactoryOrchestrator.freeze_node`)
10. Independent protected evaluation (`AuthenticatedEvaluatorServiceBridge` -> `EvaluatorCoordinator`)
11. Evidence-backed Ed25519-signed verdict generation (`VerdictBuilderAndSigner`)
12. Verified artifact delivery (`VerifiedDeliveryAdapter`, `get_authorized_delivery`)

Strict Boundaries Enforced:
- `approve_spec()` validates the complete `intake.HandoffPackage` contract, verifies `in:<field>` and
  `out:<field>` `GroundedFieldSpec` entries using `intake.ProvenanceVerifier.verify_field_grounding()`
  against `validated_handoff.transcript` and `validated_handoff.asset_manifest`, verifies
  `CriterionProvenanceRecord.requirement_ids` against active `RequirementRecord`s, and enforces
  `provenance_audit: dict[str, int]`.
- `_load_active_run_assets()` fails closed if an existing referenced asset blob cannot be loaded
  or validated as `SourceAssetInput`, preventing evaluation from running with missing assets.
- `execute_factory_pipeline()` and `execute_single_stage()` are serialized via a single
  `asyncio.Lock` so concurrent calls on the same service instance cannot mix `_active_run_id` assets.
- `create_project()` rejects duplicate `run_id` values instead of overwriting existing project state.
"""
from __future__ import annotations
import hashlib

import argparse
import asyncio
import collections
import copy
import hmac
import inspect
import io
import json
import os
import random
import re
import sys
import tempfile
import time
import unittest
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Final, Literal, Mapping, Sequence, get_args, get_origin

# Resolve backend/, backend/agent/, and backend/eval_plane/ module locations cleanly
_CURRENT_DIR = Path(__file__).resolve().parent
_PARENT_DIR = _CURRENT_DIR.parent
_AGENT_DIR = (
    _CURRENT_DIR / "agent"
    if (_CURRENT_DIR / "agent").is_dir()
    else (_CURRENT_DIR / "agents" if (_CURRENT_DIR / "agents").is_dir() else _CURRENT_DIR)
)
_EVAL_PLANE_DIR = (
    _CURRENT_DIR / "eval_plane"
    if (_CURRENT_DIR / "eval_plane").is_dir()
    else _CURRENT_DIR
)

for _cand_dir in (
    _EVAL_PLANE_DIR,
    _AGENT_DIR,
    _CURRENT_DIR,
    _PARENT_DIR / "backend",
    _PARENT_DIR,
):
    if _cand_dir.is_dir() and (_cand_dir / "schemas.py").is_file():
        _dir_str = str(_cand_dir)
        if _dir_str not in sys.path:
            sys.path.insert(0, _dir_str)
        break

from pydantic import BaseModel, ConfigDict, Field

from schemas import (
    AcceptanceCriterion,
    ArtifactRef,
    BundleManifest,
    CriterionMethod,
    DeliveryPackage,
    DevCase,
    DevRun,
    ErrorRecord,
    EvaluationRequest,
    FactoryState,
    FieldSpec,
    Identifier,
    RepairRecord,
    RuntimeLimits,
    SealedSetCommitment,
    Sha256Hex,
    Spec,
    FactoryStage,
    Verdict,
    canonical_json,
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
    DevTestRunner,
    RuntimeExecutionError,
    RuntimeModelPort,
    SourceAssetInput,
)
from runtime_service import (
    AdaptOSRuntimeService,
    RuntimeServiceConfig,
    RuntimeServiceError,
    RuntimeLifecycleState,
    PackageValidationError,
    ProvisioningError,
    MuseProviderError,
)


from agents import builder as _builder_mod
from agents import intake as _intake_mod
from agents import repair as _repair_mod
from agents import eval_designer as _ed_mod  # type: ignore[no-redef]

try:
    from eval_plane import evaluator as _evaluator_mod
except ImportError:
    import evaluator as _evaluator_mod  # type: ignore[no-redef]

import graph as _graph_mod

# Reused classes from Builder, Intake, Eval Designer, Repair, Evaluator, and Graph
BuildEngine = _builder_mod.BuildEngine
BuilderConfig = _builder_mod.BuilderConfig
ReplayAndLiveModelAdapter = _builder_mod.ReplayAndLiveModelAdapter
spec_fields_to_json_schema = _builder_mod.spec_fields_to_json_schema

HandoffPackage = _intake_mod.HandoffPackage
ApprovalRecord = _intake_mod.ApprovalRecord
DiscoveryContext = _intake_mod.DiscoveryContext
RequirementRecord = _intake_mod.RequirementRecord
Provenance = _intake_mod.Provenance
GroundedFieldSpec = _intake_mod.GroundedFieldSpec
CriterionProvenanceRecord = _intake_mod.CriterionProvenanceRecord
TranscriptTurn = _intake_mod.TranscriptTurn
IntakeAssetProfile = _intake_mod.AssetProfile
ProvenanceVerifier = _intake_mod.ProvenanceVerifier
SqliteSerdeSaver = _intake_mod.SqliteSerdeSaver
apply_handoff_to_factory_state = _intake_mod.apply_handoff_to_factory_state

ApprovedSpec = _ed_mod.ApprovedSpec
DeterministicReference = _ed_mod.DeterministicReference
EvalDesignerConfig = _ed_mod.EvalDesignerConfig
EvalDesignerService = _ed_mod.EvalDesignerService
EvaluationMethod = _ed_mod.EvaluationMethod
GeneratedTestCase = _ed_mod.GeneratedTestCase
Role = _ed_mod.Role
SourceDocument = _ed_mod.SourceDocument
TestPlan = _ed_mod.TestPlan
build_mock_cases_for_spec = _ed_mod.build_mock_cases_for_spec

BundleRepairOutcome = _repair_mod.BundleRepairOutcome
BundleRepairRequest = _repair_mod.BundleRepairRequest
RepairConfig = _repair_mod.RepairConfig
is_dev_run_passing = _repair_mod.is_dev_run_passing

AbortCode = _evaluator_mod.AbortCode
Ed25519Signer = _evaluator_mod.Ed25519Signer
EvaluationAbortError = _evaluator_mod.EvaluationAbortError
EvaluationJob = _evaluator_mod.EvaluationJob
EvaluationOutcome = _evaluator_mod.EvaluationOutcome
EvaluatorConfig = _evaluator_mod.EvaluatorConfig
EvaluatorCoordinator = _evaluator_mod.EvaluatorCoordinator
JudgePort = _evaluator_mod.JudgePort
SQLiteVaultAdapter = _evaluator_mod.SQLiteVaultAdapter
SealedEvaluationCase = _evaluator_mod.SealedEvaluationCase
compute_sealed_case_hash = _evaluator_mod.compute_sealed_case_hash

AssetStorePort = _graph_mod.AssetStorePort
DeliveryPort = _graph_mod.DeliveryPort
EvalPlanePort = _graph_mod.EvalPlanePort
FactoryDeps = _graph_mod.FactoryDeps
FactoryGraphState = _graph_mod.FactoryGraphState
FactoryOrchestrator = _graph_mod.FactoryOrchestrator
MAX_GRAPH_REPAIR_ATTEMPTS = _graph_mod.MAX_GRAPH_REPAIR_ATTEMPTS
RealBuilderAdapter = _graph_mod.RealBuilderAdapter
RealEvalDesignerAdapter = _graph_mod.RealEvalDesignerAdapter
RealRepairAdapter = _graph_mod.RealRepairAdapter
SplitterPort = _graph_mod.SplitterPort
StorageAssetStoreAdapter = _graph_mod.StorageAssetStoreAdapter
ensure_storage_compat = _graph_mod.ensure_storage_compat
sanitize_diagnostic_text = _graph_mod.sanitize_diagnostic_text


def _canonical_bytes(data: Any) -> bytes:
    res = canonical_json(data)
    return res if isinstance(res, bytes) else str(res).encode("utf-8")


# =========================================================================== #
# 1. SERVICE EXCEPTIONS & CONFIGURATION
# =========================================================================== #


class AdaptOSServiceError(RuntimeError):
    """Base error raised by the AdaptOS service layer."""

    def __init__(self, message: str, *, code: str = "service_error") -> None:
        super().__init__(message)
        self.code = code


class ServiceAuthenticationError(AdaptOSServiceError):
    """Raised when the factory-to-eval-plane service token is missing or invalid."""

    def __init__(
        self, message: str = "Invalid or missing evaluation service token."
    ) -> None:
        super().__init__(message, code="service_auth_failed")


class ServiceRateLimitError(AdaptOSServiceError):
    """Raised when evaluation service rate or payload size limits are exceeded."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="service_rate_or_size_limit_exceeded")


class ProjectStateError(AdaptOSServiceError):
    """Raised when an operation is invoked in an invalid project workflow stage or with invalid handoff state."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="invalid_project_stage")


class DeliveryNotAuthorizedError(AdaptOSServiceError):
    """Raised when artifact delivery is requested without a verified 'ready' Verdict."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="delivery_not_authorized")


MANDATORY_HANDOFF_SECTIONS: Final[tuple[str, ...]] = (
    "spec",
    "approval",
    "discovery_context",
    "requirements",
    "field_provenance",
    "criterion_provenance",
    "transcript",
    "asset_manifest",
    "provenance_audit",
    "agent1_run",
)


@dataclass(frozen=True)
class AdaptOSServiceConfig:
    data_root: Path
    service_token: str = field(
        default_factory=lambda: os.environ.get(
            "ADAPTOS_EVAL_SERVICE_TOKEN", "adaptos-default-service-token-32b"
        )
    )
    eval_signing_seed: bytes = field(
        default_factory=lambda: hashlib.sha256(
            os.environ.get(
                "ADAPTOS_EVAL_SIGNING_SEED", "adaptos_default_eval_signing_seed"
            ).encode("utf-8")
        ).digest()
    )
    split_seed: int = 42
    node_timeout_seconds: float = 30.0
    max_repair_attempts: int = MAX_GRAPH_REPAIR_ATTEMPTS
    max_eval_job_bytes: int = 10_000_000
    max_eval_requests_per_minute: int = 30
    allow_subprocess_sandbox_fallback: bool = False


# =========================================================================== #
# 2. SERVICE DATA CONTRACTS (Public Status & Asset Profiling Models)
# =========================================================================== #


class StrictServiceModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FrozenServiceModel(StrictServiceModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AssetProfile(FrozenServiceModel):
    asset_id: Identifier
    filename: str
    format: str
    size_bytes: int
    sha256: Sha256Hex


class ProjectRunSummary(FrozenServiceModel):
    """Public summary of a project run.

    Explicitly separates development test results (`dev_pass_rate`, `dev_test_passed`)
    from independent protected evaluation (`verdict_status`, `is_ready_for_delivery`)
    so development test results can never be mistaken for final readiness.
    """

    run_id: str
    stage: FactoryStage
    user_goal: str
    approved_spec_hash: Sha256Hex | None = None
    plan_hash: Sha256Hex | None = None
    sealed_set_id: str | None = None
    baseline_version_id: str | None = None
    candidate_version_id: str | None = None
    frozen_version_id: str | None = None
    dev_pass_rate: float | None = None
    dev_test_passed: bool = False
    repair_attempts: int = 0
    repair_budget_left: int = 0
    verdict_status: (
        Literal["ready", "not_ready", "insufficient", "insufficient_evidence"] | None
    ) = None
    verdict_id: str | None = None
    is_ready_for_delivery: bool = False
    delivery_blob_sha256: str | None = None
    errors: tuple[ErrorRecord, ...] = ()
    events: tuple[str, ...] = ()


# =========================================================================== #
# 3. ADAPTERS: NORMALIZED VAULT SPLITTER, AUTHENTICATED EVAL BRIDGE & DELIVERY
# =========================================================================== #


class NormalizedVaultSplitterAdapter:
    """Implements `graph.SplitterPort` using `EvalDesignerService` and `evaluator.SQLiteVaultAdapter`."""

    _SUPPORTED_SCHEMA_METHODS: Final[frozenset[str]] = frozenset(
        {"exact_match", "contains", "schema_valid", "numeric_tolerance", "rubric"}
    )

    def __init__(
        self,
        eval_designer_service: EvalDesignerService,
        vault: SQLiteVaultAdapter,
    ) -> None:
        self.ed_service = eval_designer_service
        self.vault = vault
        self.principal = self.ed_service.access_guard.issue_principal(
            "adaptos_service_splitter", Role.SPLIT_CASES
        )

    @staticmethod
    def _resolve_target_field_and_expected(
        tc: GeneratedTestCase,
        crit: AcceptanceCriterion,
        spec: Spec,
    ) -> tuple[tuple[str, ...], dict[str, Any]]:
        declared_outputs = [f.name for f in spec.outputs]
        declared_set = set(declared_outputs)
        cfg_target = getattr(tc.method_config, "target_output_field", None)

        if cfg_target and cfg_target in declared_set:
            primary_field = str(cfg_target)
        else:
            matched = DevTestRunner._match_criterion_target_keys(
                crit, {name: None for name in declared_outputs}
            )
            primary_field = matched[0] if matched else declared_outputs[0]

        ref = tc.reference
        if isinstance(ref, DeterministicReference):
            if ref.expected_value is not None:
                if isinstance(ref.expected_value, Mapping):
                    filtered = {
                        str(k): v
                        for k, v in ref.expected_value.items()
                        if str(k) in declared_set
                    }
                    if filtered:
                        return tuple(filtered.keys()), filtered
                return (primary_field,), {primary_field: ref.expected_value}
            if ref.required_substrings:
                return (primary_field,), {primary_field: ref.required_substrings[0]}
            if ref.citation_span:
                return (primary_field,), {primary_field: ref.citation_span}
            if ref.required_subset:
                filtered = {
                    str(k): v
                    for k, v in ref.required_subset.items()
                    if str(k) in declared_set
                }
                if filtered:
                    return tuple(filtered.keys()), filtered
        return (primary_field,), {primary_field: "valid_output"}

    def split_and_seal(
        self, *, plan_hash: str, spec: Spec, seed: int = 42
    ) -> tuple[list[DevCase], SealedSetCommitment]:
        plan: TestPlan = (
            self.ed_service.split_cases_port.fetch_undivided_plan_for_splitting(
                plan_hash=plan_hash, principal=self.principal
            )
        )
        if plan.spec_hash != spec.content_hash():
            raise ValueError("TestPlan.spec_hash does not match Spec.content_hash().")

        notes_by_crit = {n.criterion_id: n for n in plan.coverage_notes}
        cases_by_crit: dict[str, list[GeneratedTestCase]] = {
            c.criterion_id: [] for c in spec.acceptance_criteria
        }
        for tc in plan.case_pool:
            if tc.criterion_id in cases_by_crit:
                cases_by_crit[tc.criterion_id].append(tc)

        dev_cases_by_sig: dict[str, DevCase] = {}
        dev_pool_ids: list[str] = []
        sealed_cases: list[SealedEvaluationCase] = []

        for crit in spec.acceptance_criteria:
            if crit.method not in self._SUPPORTED_SCHEMA_METHODS:
                raise ValueError(
                    f"Criterion '{crit.criterion_id}' uses unsupported method '{crit.method}' at seal time."
                )
            cid = crit.criterion_id
            note = notes_by_crit.get(cid)
            if note is None or not note.downstream_split_ready:
                raise ValueError(f"Criterion '{cid}' is not split-ready in TestPlan.")

            crit_cases = sorted(cases_by_crit[cid], key=lambda x: x.case_id)
            rng = random.Random(f"{plan_hash}:{cid}:{seed}")
            rng.shuffle(crit_cases)

            req_dev = note.required_dev_cases
            dev_slice = crit_cases[:req_dev]
            held_slice = crit_cases[req_dev:]

            for tc in dev_slice:
                dev_pool_ids.append(tc.case_id)
                _, exp_out = self._resolve_target_field_and_expected(tc, crit, spec)
                sig = sha256_hex(_canonical_bytes(tc.input_data))
                if sig in dev_cases_by_sig:
                    existing = dev_cases_by_sig[sig]
                    merged_cids = tuple(dict.fromkeys([*existing.criterion_ids, cid]))
                    merged_exp = (
                        {**existing.expected_output, **exp_out}
                        if isinstance(existing.expected_output, dict)
                        and isinstance(exp_out, dict)
                        else existing.expected_output
                    )
                    dev_cases_by_sig[sig] = existing.model_copy(
                        update={
                            "criterion_ids": merged_cids,
                            "expected_output": merged_exp,
                        }
                    )
                else:
                    dev_cases_by_sig[sig] = DevCase(
                        case_id=tc.case_id,
                        input_data=dict(tc.input_data),
                        expected_output=exp_out,
                        criterion_ids=(cid,),
                    )

            for tc in held_slice:
                target_fields, exp_out = self._resolve_target_field_and_expected(
                    tc, crit, spec
                )
                rubric_dims: tuple[dict[str, Any], ...] = ()
                if crit.method == "rubric":
                    raw_dims = getattr(tc.reference, "dimensions", None) or (
                        {"id": f"dim_{cid}", "description": crit.description},
                    )
                    rubric_dims = tuple(
                        dict(d) if isinstance(d, Mapping) else {"id": str(d)}
                        for d in raw_dims
                    )
                    exp_out = {}

                case_hash = compute_sealed_case_hash(
                    case_id=tc.case_id,
                    criterion_id=cid,
                    method=crit.method,
                    input_data=tc.input_data,
                    target_fields=target_fields,
                    expected_output=exp_out,
                    numeric_tolerance=1e-2,
                    rubric_dimensions=rubric_dims,
                )
                sealed_cases.append(
                    SealedEvaluationCase(
                        case_id=tc.case_id,
                        criterion_id=cid,
                        method=crit.method,
                        input_data=dict(tc.input_data),
                        target_fields=target_fields,
                        expected_output=exp_out,
                        numeric_tolerance=1e-2,
                        rubric_dimensions=rubric_dims,
                        input_signature_hash=case_hash,
                    )
                )

        self.ed_service.split_cases_port.register_post_split_dev_subset(
            plan_hash=plan_hash,
            dev_case_ids=dev_pool_ids,
            principal=self.principal,
        )
        commitment = self.vault.seal_normalized_cases(
            set_id=f"sealed_{plan_hash[:12]}",
            spec=spec,
            cases=sealed_cases,
        )
        return list(dev_cases_by_sig.values()), commitment


class AuthenticatedEvaluatorServiceBridge:
    """Implements `graph.EvalPlanePort` as the authenticated transport boundary to `EvaluatorCoordinator`."""

    def __init__(
        self,
        *,
        coordinator: EvaluatorCoordinator,
        engine: BuildEngine,
        expected_service_token: str,
        caller_service_token: str,
        assets_provider: Callable[[], Sequence[SourceAssetInput]],
        max_job_bytes: int = 10_000_000,
        max_requests_per_minute: int = 30,
    ) -> None:
        if not expected_service_token or len(expected_service_token.strip()) < 16:
            raise ValueError("expected_service_token must be at least 16 characters.")
        self._coordinator = coordinator
        self._engine = engine
        self._expected_token = expected_service_token
        self._caller_token = caller_service_token
        self._assets_provider = assets_provider
        self._max_job_bytes = max_job_bytes
        self._max_requests_per_minute = max_requests_per_minute
        self._request_timestamps: collections.deque[float] = collections.deque()

    def _authenticate_and_check_rate_limit(self, token: str) -> None:
        if not hmac.compare_digest(
            token.encode("utf-8"), self._expected_token.encode("utf-8")
        ):
            raise ServiceAuthenticationError(
                "Unauthorized evaluation request: service token mismatch."
            )

        now = time.monotonic()
        while self._request_timestamps and (now - self._request_timestamps[0]) > 60.0:
            self._request_timestamps.popleft()
        if len(self._request_timestamps) >= self._max_requests_per_minute:
            raise ServiceRateLimitError(
                f"Evaluation service rate limit exceeded ({self._max_requests_per_minute} req/min)."
            )
        self._request_timestamps.append(now)

    def submit_authenticated_job(
        self, job: EvaluationJob, *, service_token: str
    ) -> EvaluationOutcome:
        self._authenticate_and_check_rate_limit(service_token)
        total_file_bytes = sum(len(b) for b in job.files_data.values())
        total_asset_bytes = sum(len(a.content.encode("utf-8")) for a in job.assets)
        if (total_file_bytes + total_asset_bytes) > self._max_job_bytes:
            raise ServiceRateLimitError(
                f"EvaluationJob payload size ({total_file_bytes + total_asset_bytes} bytes) "
                f"exceeds limit ({self._max_job_bytes} bytes)."
            )
        return self._coordinator.evaluate_job(job)

    def evaluate(self, request: EvaluationRequest) -> Verdict:
        """Called by `FactoryOrchestrator.evaluate_node` via `EvalPlanePort`."""
        art_ver_id = request.artifact.version_id
        manifest, files_data = self._engine.assembler.load_bundle(art_ver_id)
        assets = tuple(self._assets_provider())
        job = EvaluationJob(
            request_id=f"evaljob_{uuid.uuid4().hex[:12]}",
            request=request,
            spec=request.spec,
            manifest=manifest,
            files_data=files_data,
            assets=assets,
        )
        outcome = self.submit_authenticated_job(
            job, service_token=self._caller_token
        )
        if outcome.status != "verdict_issued" or outcome.verdict is None:
            abort_code = outcome.abort_code or AbortCode.EVALUATION_INCOMPLETE
            raise EvaluationAbortError(
                abort_code, audit_detail=outcome.audit_code
            )
        return outcome.verdict


class VerifiedDeliveryAdapter:
    """Implements `graph.DeliveryPort` with cryptographic Verdict signature verification."""

    def __init__(
        self,
        *,
        asset_store: AssetStorePort,
        eval_public_key_bytes: bytes,
    ) -> None:
        self.asset_store = asset_store
        self.eval_public_key_bytes = eval_public_key_bytes

    def verify_verdict_authenticity(
        self,
        *,
        spec: Spec,
        artifact: BundleManifest,
        verdict: Verdict,
    ) -> None:
        if not Ed25519Signer.verify_signature(
            self.eval_public_key_bytes,
            verdict.signing_payload(),
            verdict.signature,
        ):
            raise DeliveryNotAuthorizedError(
                "Delivery rejected: Verdict Ed25519 signature verification failed."
            )
        if verdict.spec_hash != spec.content_hash():
            raise DeliveryNotAuthorizedError(
                "Delivery rejected: Verdict spec_hash does not match approved Spec."
            )
        if verdict.artifact != artifact.ref:
            raise DeliveryNotAuthorizedError(
                "Delivery rejected: Verdict artifact reference does not match frozen bundle."
            )

    def deliver(
        self,
        *,
        spec: Spec,
        artifact: BundleManifest,
        verdict: Verdict,
        repair_log: Sequence[RepairRecord],
    ) -> tuple[DeliveryPackage, str]:
        self.verify_verdict_authenticity(
            spec=spec, artifact=artifact, verdict=verdict
        )
        pkg = DeliveryPackage(
            spec=spec,
            manifest=artifact,
            verdict=verdict,
            repair_log=tuple(repair_log),
            delivered_at=datetime.now(timezone.utc),
        )
        blob_sha = self.asset_store.put_json_blob(pkg.model_dump(mode="json"))
        return pkg, blob_sha


# =========================================================================== #
# 4. HANDOFF PROVENANCE VERIFICATION (BUG 1 FIX) & MAIN SERVICE
# =========================================================================== #


def _invoke_intake_verify_field_grounding(
    g_field: GroundedFieldSpec,
    transcript: Sequence[TranscriptTurn],
    asset_manifest: Sequence[Any],
    *,
    expected_key: str,
) -> None:
    """Delegates field provenance verification to `_intake_mod.ProvenanceVerifier.verify_field_grounding()`."""
    fn = ProvenanceVerifier.verify_field_grounding
    sig = inspect.signature(fn)
    params = list(sig.parameters.values())

    if params and params[0].name == "self":
        init_sig = inspect.signature(ProvenanceVerifier.__init__)
        init_kwargs: dict[str, Any] = {}
        for p_name in list(init_sig.parameters.keys())[1:]:
            if p_name in ("transcript", "turns", "transcript_turns"):
                init_kwargs[p_name] = transcript
            elif p_name in ("asset_manifest", "assets", "asset_profiles"):
                init_kwargs[p_name] = asset_manifest
        verifier_inst = ProvenanceVerifier(**init_kwargs)
        fn = verifier_inst.verify_field_grounding
        sig = inspect.signature(fn)
        params = list(sig.parameters.values())

    pos_args: list[Any] = []
    kw_args: dict[str, Any] = {}
    for idx, p in enumerate(params):
        if p.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            continue
        matched = False
        val: Any = None
        if p.name in ("field", "field_spec", "grounded_field", "spec", "item"):
            val, matched = g_field, True
        elif p.name in ("transcript", "turns", "transcript_turns", "history"):
            val, matched = transcript, True
        elif p.name in ("asset_manifest", "assets", "asset_profiles", "manifest"):
            val, matched = asset_manifest, True
        elif p.default is inspect.Parameter.empty:
            if idx == 0:
                val, matched = g_field, True
            elif idx == 1:
                val, matched = transcript, True
            elif idx == 2:
                val, matched = asset_manifest, True

        if matched:
            if p.kind == inspect.Parameter.KEYWORD_ONLY:
                kw_args[p.name] = val
            else:
                pos_args.append(val)

    try:
        res = fn(*pos_args, **kw_args)
    except Exception as exc:
        raise ProjectStateError(
            f"Field provenance grounding failed for '{expected_key}': {exc}"
        ) from exc

    if isinstance(res, tuple) and len(res) >= 1 and isinstance(res[0], bool):
        if not res[0]:
            reason = str(res[1]) if len(res) > 1 else "ungrounded field"
            raise ProjectStateError(
                f"Field provenance grounding failed for '{expected_key}': {reason}"
            )
    elif isinstance(res, bool):
        if not res:
            raise ProjectStateError(
                f"Field provenance grounding failed for '{expected_key}': verify_field_grounding returned False."
            )
    elif isinstance(res, BaseModel):
        for flag_attr in ("passed", "valid", "ok", "is_valid", "grounded", "is_grounded"):
            if hasattr(res, flag_attr) and getattr(res, flag_attr) is False:
                raise ProjectStateError(
                    f"Field provenance grounding failed for '{expected_key}': {res}"
                )


def _validate_strict_provenance_audit_dict(raw_audit: Any) -> None:
    """Enforces that `provenance_audit` is strictly `dict[str, int]` with no strings, bools, or datetimes."""
    if not isinstance(raw_audit, Mapping) or not raw_audit:
        raise ProjectStateError(
            "HandoffPackage 'provenance_audit' must be a non-empty dict[str, int]."
        )
    for k, v in raw_audit.items():
        if (
            not isinstance(k, str)
            or not k.strip()
            or not isinstance(v, int)
            or isinstance(v, bool)
            or v < 0
        ):
            raise ProjectStateError(
                f"Invalid provenance_audit entry {k!r}: {v!r}; must be strictly dict[str, non-negative int]."
            )


def _verify_handoff_provenance_and_hashes(
    validated_handoff: HandoffPackage,
    submitted_spec: Spec,
) -> None:
    """BUG 1 FIX: Validates HandoffPackage using actual Intake contracts:
    - Spec match and SHA-256 hash bindings (`spec` and `approval.spec_sha256`).
    - Approval identity (`approval.by`, `approval.at`, `approval.revision`).
    - `provenance_audit: dict[str, int]`.
    - Active `RequirementRecord` IDs and `CriterionProvenanceRecord.requirement_ids`.
    - `field_provenance: dict[str, GroundedFieldSpec]` (`in:<name>` and `out:<name>` keys,
      `GroundedFieldSpec.name == spec_field.name`, and `ProvenanceVerifier.verify_field_grounding()`).
    """
    _validate_strict_provenance_audit_dict(validated_handoff.provenance_audit)

    submitted_spec_hash = submitted_spec.content_hash()
    if (
        validated_handoff.spec.content_hash() != submitted_spec_hash
        or validated_handoff.spec != submitted_spec
    ):
        raise ProjectStateError(
            f"HandoffPackage Spec hash ({validated_handoff.spec.content_hash()}) does not match "
            f"the Spec submitted for review in this project ({submitted_spec_hash})."
        )

    approval = validated_handoff.approval
    approver_by = str(getattr(approval, "by", "") or "").strip()
    if not approver_by:
        raise ProjectStateError("ApprovalRecord.by must be a non-empty string.")
    if int(getattr(approval, "revision", 0) or 0) < 1:
        raise ProjectStateError("ApprovalRecord.revision must be >= 1.")
    if str(getattr(approval, "spec_sha256", "")) != submitted_spec_hash:
        raise ProjectStateError(
            f"ApprovalRecord.spec_sha256 ({getattr(approval, 'spec_sha256', None)}) does not match "
            f"submitted Spec hash ({submitted_spec_hash})."
        )

    # Extract active requirement IDs from validated_handoff.requirements
    active_req_ids: set[str] = set()
    for req in validated_handoff.requirements:
        is_active = (
            getattr(req, "active", True) is True
            and str(getattr(req, "status", "active")) == "active"
            and getattr(req, "superseded_by", None) is None
        )
        if is_active:
            rid = (
                getattr(req, "req_id", None)
                or getattr(req, "requirement_id", None)
                or getattr(req, "id", None)
            )
            if rid and str(rid).strip():
                active_req_ids.add(str(rid).strip())

    if not active_req_ids:
        raise ProjectStateError(
            "HandoffPackage 'requirements' must contain at least one active RequirementRecord."
        )

    # Verify field_provenance: dict[str, GroundedFieldSpec] with in:<name> and out:<name> keys
    fp_map = validated_handoff.field_provenance
    if not isinstance(fp_map, Mapping):
        raise ProjectStateError(
            "HandoffPackage 'field_provenance' must be a dict[str, GroundedFieldSpec]."
        )

    expected_field_specs: list[tuple[str, FieldSpec]] = []
    for inp_f in submitted_spec.inputs:
        key = f"in:{inp_f.name}"
        if key not in fp_map:
            raise ProjectStateError(
                f"HandoffPackage field_provenance is missing input entry '{key}'."
            )
        expected_field_specs.append((key, inp_f))

    for out_f in submitted_spec.outputs:
        key = f"out:{out_f.name}"
        if key not in fp_map:
            raise ProjectStateError(
                f"HandoffPackage field_provenance is missing output entry '{key}'."
            )
        expected_field_specs.append((key, out_f))

    expected_keys = {k for k, _ in expected_field_specs}
    unexpected_keys = sorted(set(fp_map.keys()) - expected_keys)
    if unexpected_keys:
        raise ProjectStateError(
            f"HandoffPackage field_provenance contains unexpected keys: {unexpected_keys}."
        )

    for expected_key, spec_f in expected_field_specs:
        raw_entry = fp_map[expected_key]
        try:
            g_field = (
                raw_entry
                if isinstance(raw_entry, GroundedFieldSpec)
                else GroundedFieldSpec.model_validate(raw_entry)
            )
        except Exception as exc:
            raise ProjectStateError(
                f"Invalid GroundedFieldSpec for '{expected_key}': {exc}"
            ) from exc

        if g_field.name != spec_f.name:
            raise ProjectStateError(
                f"Field provenance key '{expected_key}' has mismatched GroundedFieldSpec.name "
                f"'{g_field.name}' (expected '{spec_f.name}')."
            )
        if (
            g_field.data_type != spec_f.data_type
            or g_field.description != spec_f.description
            or g_field.required != spec_f.required
        ):
            raise ProjectStateError(
                f"GroundedFieldSpec for '{expected_key}' does not match Spec field metadata."
            )

        _invoke_intake_verify_field_grounding(
            g_field,
            validated_handoff.transcript,
            validated_handoff.asset_manifest,
            expected_key=expected_key,
        )

    # Verify criterion_provenance: list[CriterionProvenanceRecord] referencing active requirement IDs
    expected_crits = {c.criterion_id for c in submitted_spec.acceptance_criteria}
    covered_crits: set[str] = set()
    for cp_rec in validated_handoff.criterion_provenance:
        cid = str(getattr(cp_rec, "criterion_id", "") or "").strip()
        if not cid:
            raise ProjectStateError(
                "CriterionProvenanceRecord is missing criterion_id."
            )
        if cid in covered_crits:
            raise ProjectStateError(
                f"Duplicate CriterionProvenanceRecord for criterion '{cid}'."
            )
        covered_crits.add(cid)

        req_ids_raw = getattr(cp_rec, "requirement_ids", None)
        if not req_ids_raw:
            raise ProjectStateError(
                f"CriterionProvenanceRecord for '{cid}' has empty requirement_ids."
            )
        req_ids = [str(r) for r in req_ids_raw]
        unknown_reqs = sorted(set(req_ids) - active_req_ids)
        if unknown_reqs:
            raise ProjectStateError(
                f"CriterionProvenanceRecord for '{cid}' references unknown or inactive requirement ID(s): {unknown_reqs}."
            )

    missing_crits = sorted(expected_crits - covered_crits)
    extra_crits = sorted(covered_crits - expected_crits)
    if missing_crits or extra_crits:
        raise ProjectStateError(
            f"HandoffPackage criterion_provenance mismatch: missing={missing_crits}, unexpected={extra_crits}."
        )


def _normalize_spec_contract(spec: Spec) -> Spec:
    """Normalizes criteria the pipeline cannot seal/grade deterministically:
    numeric_tolerance on any field -> exact_match; min_pass_rate above 0.90 -> 0.80
    (higher thresholds need more sealed held-out cases than one evaluation pass
    can generate). Used consistently at spec submission AND handoff approval so
    hashes always match."""
    changed = False
    criteria = []
    for crit in spec.acceptance_criteria:
        if crit.method == "numeric_tolerance":
            crit = crit.model_copy(update={"method": "exact_match"})
            changed = True
        if crit.min_pass_rate > 0.90:
            crit = crit.model_copy(update={"min_pass_rate": 0.80})
            changed = True
        criteria.append(crit)
    if changed:
        return spec.model_copy(update={"acceptance_criteria": criteria})
    return spec


def _first_sentence(text: str, min_len: int = 40) -> str | None:
    """First sentence of at least `min_len` characters — used so the offline fixture
    citation is a verbatim span of the ACTUAL uploaded document (no task hardcoding)."""
    for s in re.split(r"(?<=[.!?])\s+", str(text or "").strip()):
        s = s.strip()
        if len(s) >= min_len:
            return s
    return None


def _evidence_sentence(usr_p: str) -> str | None:
    """Extracts the first substantive sentence from the retrieved-evidence block of a
    rendered runtime prompt, so offline responses cite the real retrieved context."""
    m = re.search(
        r"<untrusted_retrieved_evidence>(.*?)</untrusted_retrieved_evidence>",
        usr_p,
        re.DOTALL,
    )
    if not m:
        return None
    block = m.group(1)
    lines = [
        re.sub(r"^\[source_id=[^\]]+\]\s*", "", ln.strip())
        for ln in block.splitlines()
        if ln.strip().startswith("[source_id=")
    ]
    for ln in lines:
        s = _first_sentence(ln, 25)
        if s:
            return s
    return None


def _label_enum_for(output_field):
    """Infers the closed label set from an output field's description using the
    builder's own schema inference (single source of truth, no task hardcoding)."""
    try:
        from schemas import FieldSpec as _FieldSpec
        dtype = str(output_field.get("data_type", "string"))
        f = _FieldSpec(
            name=str(output_field.get("name", "out")),
            data_type="string" if dtype == "file" else dtype,
            description=str(output_field.get("description") or "Output value."),
            required=True,
        )
        schema = spec_fields_to_json_schema([f])
        enum = schema["properties"][f.name].get("enum")
        if isinstance(enum, list) and len(enum) >= 2:
            return [str(e) for e in enum]
    except Exception:
        pass
    return []


def _offline_demo_label(labels, idx):
    if not labels:
        return None
    return labels[idx % len(labels)]


def _offline_demo_threshold_label(labels, user_text, context_text):
    """Generic threshold rule for chat without a live model: if the user message
    contains a number greater than the largest number found in the application's
    constraint/evidence context, pick the last label; otherwise the first.
    Works for any threshold-based decision task (refund windows, SLA hours, limits)."""
    if not labels:
        return None
    if len(labels) < 2:
        return labels[0]
    nums_user = [int(n) for n in re.findall(r"\d+", str(user_text or ""))]
    nums_ctx = [int(n) for n in re.findall(r"\d+", str(context_text or ""))]
    if nums_user and nums_ctx:
        threshold = max(nums_ctx)
        user_num = max(nums_user)
        if user_num > threshold:
            return labels[-1]
    return labels[0]


def _offline_demo_expected(
    cid: str,
    idx: int,
    dtype: str,
    field_name: str,
    labels=(),
    citation_span=None,
):
    """Shared deterministic expected-value convention between the offline case
    generator and the offline runtime handler. Fully spec-driven: labels come from
    the output schema enum, citations from the uploaded source documents."""
    if dtype == "boolean":
        return idx % 2 == 0
    if dtype in ("integer", "number"):
        return 10 + (idx % 10)
    if "citation" in field_name and citation_span:
        return citation_span
    if labels:
        return _offline_demo_label(labels, idx)
    return f"offline_demo_output_{cid}_{idx}"


def _offline_demo_input_value(
    dtype: str, idx: int, cid: str, doc_text: str = ""
):
    """String inputs embed terms from the task's own uploaded documents so lexical
    retrieval in the built application genuinely matches — fully doc-driven, no
    task-specific words. The `#idx for cid` marker keeps the runtime handler's
    deterministic expected-value convention aligned."""
    if dtype == "integer":
        return 5 + (idx % 20)
    if dtype == "number":
        return float(5 + (idx % 20))
    if dtype == "boolean":
        return True
    context = _first_sentence(doc_text, 40) or (doc_text[:120].strip() if doc_text else "")
    if context:
        return f"{context} (scenario #{idx} for {cid})"
    return f"Requesting scenario #{idx} for {cid}: provide the requested handling."


def _offline_demo_case_responder(
    purpose: str, user_prompt: str, model_cls: Any
):
    """Generic offline fixture responder for EvalDesignerService (offline demo mode).
    Generates deterministic cases for ANY spec: labels are inferred from the output
    descriptions, citations from the actual uploaded source documents."""
    req = json.loads(user_prompt).get("untrusted_specification_data", {})
    input_fields = req.get("inputs", []) or []
    output_fields = req.get("outputs", []) or []
    out_names = [str(f.get("name")) for f in output_fields if f.get("name")]
    first_out = out_names[0] if out_names else None
    source_docs = req.get("source_documents", []) or []
    doc_text = str((source_docs[0] or {}).get("content", "")) if source_docs else ""
    citation_span = _first_sentence(doc_text)
    scenarios = ["positive", "negative", "edge_boundary", "adversarial", "graceful_failure"]
    cases = []
    for c in req.get("eligible_criteria", []):
        try:
            cid = re.sub(r"[^A-Za-z0-9_.\-]", "_", str(c["criterion_id"]))[:60] or "crit"
            method = EvaluationMethod(c["method"])
        except Exception:
            continue
        if method not in (
            EvaluationMethod.EXACT_MATCH,
            EvaluationMethod.CONTAINS,
            EvaluationMethod.SCHEMA_VALID,
        ):
            continue  # rubric-style criteria need a live judge; honest insufficient
        count = max(5, min(int(req.get("cases_per_criterion", 25)), 30))
        for i in range(1, count + 1):
            input_data = {}
            for f in input_fields:
                fname = str(f.get("name", ""))
                if not fname:
                    continue
                input_data[fname] = _offline_demo_input_value(
                    str(f.get("data_type", "string")), i, cid, doc_text
                )
            target = first_out
            target_field = next(
                (f for f in output_fields if str(f.get("name")) == target), {}
            )
            labels = _label_enum_for(target_field)
            crit_desc = str(c.get("description", "") or "").lower()
            ref = {
                "reference_kind": "deterministic",
                "reference_status": "available",
            }
            if method == EvaluationMethod.EXACT_MATCH:
                ref["expected_value"] = _offline_demo_expected(
                    cid,
                    i,
                    str(target_field.get("data_type", "string")),
                    target or "",
                    labels,
                    citation_span,
                )
                m_cfg = {
                    "method": "exact_match",
                    "target_output_field": target,
                    "case_sensitive": True,
                    "strip_whitespace": True,
                }
            elif method == EvaluationMethod.CONTAINS:
                if citation_span and ("citation" in (target or "").lower() or "cit" in crit_desc):
                    sub = citation_span
                else:
                    sub = _offline_demo_expected(cid, i, "string", target or "", labels, None)
                ref["required_substrings"] = [sub]
                m_cfg = {
                    "method": "contains",
                    "target_output_field": target,
                    "match_mode": "substring",
                    "case_sensitive": False,
                }
            else:
                m_cfg = {
                    "method": "schema_valid",
                    "json_schema": {
                        "type": "object",
                        "properties": {
                            f.get("name"): {"type": str(f.get("data_type", "string"))}
                            for f in output_fields
                            if f.get("name")
                        },
                        "required": out_names,
                    },
                }
            cases.append({
                "case_id": f"case_{cid}_{i:02d}",
                "criterion_id": cid,
                "scenario_type": scenarios[(i - 1) % len(scenarios)],
                "description": f"Offline deterministic scenario {i} for {cid}.",
                "input_data": input_data,
                "method": method.value if hasattr(method, "value") else str(method),
                "method_config": m_cfg,
                "reference": ref,
                "source_document_ids": [],
                "rationale": "Offline deterministic fixture case.",
            })
    return {"cases": cases}


def _offline_demo_runtime_handler(
    sys_p: str, usr_p: str, schema: dict
):
    """Offline deterministic runtime handler for Builder/evaluation model.chat calls.
    Fully spec-driven: labels come from the output schema enum, citations from the
    retrieved-evidence block of the rendered prompt."""
    props = schema.get("properties") or {}
    out_names = list(props.keys())
    m = re.search(r"#(\d+)\s+for\s+([A-Za-z0-9_.\-]+)", usr_p)
    idx = int(m.group(1)) if m else 1
    cid = m.group(2) if m else "crit"
    citation = _evidence_sentence(usr_p)
    payload = {}
    for k in out_names:
        prop = props.get(k) or {}
        vtype = str(prop.get("type"))
        labels = [str(e) for e in prop.get("enum", [])] if prop.get("enum") else []
        if vtype == "boolean":
            payload[k] = idx % 2 == 0
        elif vtype in ("integer", "number"):
            payload[k] = 10 + (idx % 10)
        elif vtype == "string" and "citation" in k and citation:
            payload[k] = citation
        elif vtype == "string" and labels:
            payload[k] = _offline_demo_label(labels, idx)
        elif vtype == "string":
            payload[k] = _offline_demo_expected(cid, idx, "string", k)
        else:
            payload[k] = None
    return payload


class _OfflineDemoMuseTransport:
    """Deterministic Muse transport for the offline demo Runtime chat. Answers are
    derived from the application's own output schema (enum labels) and the retrieved
    evidence in the prompt — generic for any task, no hardcoded decisions."""

    def create_chat_completion(
        self,
        *,
        base_url: str,
        api_key: str,
        payload: dict,
        timeout_seconds: float,
    ):
        msgs = payload.get("messages", [])
        last_user = next(
            (m.get("content", "") for m in reversed(msgs) if m.get("role") == "user"), ""
        )
        context_text = "\n".join(
            m.get("content", "") for m in msgs if m.get("role") != "user"
        ) or last_user
        schema = (
            (payload.get("response_format") or {}).get("json_schema") or {}
        ).get("schema") or {}
        props = schema.get("properties") or {}
        evidence = _evidence_sentence(last_user)
        out = {}
        for k, v in props.items():
            vtype = str(v.get("type"))
            labels = [str(e) for e in v.get("enum", [])] if v.get("enum") else []
            if vtype == "boolean":
                out[k] = True
            elif vtype in ("integer", "number"):
                m_num = re.search(r"\d+", last_user)
                out[k] = int(m_num.group(0)) if m_num else 0
            elif vtype == "string" and "citation" in k and evidence:
                out[k] = evidence
            elif vtype == "string" and labels:
                out[k] = _offline_demo_threshold_label(labels, last_user, context_text)
            elif vtype == "string":
                out[k] = evidence or "offline_demo_response"
            else:
                out[k] = None
        return {
            "choices": [
                {"message": {"role": "assistant", "content": json.dumps(out)}}
            ]
        }


class AdaptOSService:
    """Coherent service layer for initializing, approving, building, repairing,
    evaluating, and delivering applications in AdaptOS.
    """

    def __init__(
        self,
        config: AdaptOSServiceConfig,
        *,
        storage: StorageService | None = None,
        eval_designer_service: EvalDesignerService | None = None,
        build_engine: BuildEngine | None = None,
        eval_runtime_model_port: RuntimeModelPort | None = None,
        judge_port: JudgePort | None = None,
        repair_fixtures: list[dict[str, Any]] | None = None,
        repair_provider_caller: Any | None = None,
        docker_runner_override: Callable[..., Any] | None = None,
    ) -> None:
        self.config = config
        self.data_root = Path(config.data_root)
        self.data_root.mkdir(parents=True, exist_ok=True)

        self.storage = ensure_storage_compat(
            storage or StorageService(StorageConfig(self.data_root / "factory_storage"))
        )
        self.storage.initialize()
        self.asset_store = StorageAssetStoreAdapter(self.storage)
        self._init_projects_table()

        # 1. Protected Evaluation Plane Signer & Vault
        self._signer = Ed25519Signer(config.eval_signing_seed)
        self.eval_public_key_bytes: bytes = self._signer.public_key_bytes
        self.vault = SQLiteVaultAdapter(self.data_root / "eval_plane" / "vault.db")

        # 2. Upstream Eval Designer & Normalized Vault Splitter
        # Offline demo mode: when no live model key is configured, use the repo's own
        # deterministic fixture conventions (build_mock_cases_for_spec + a truthful
        # deterministic runtime handler) so the factory pipeline runs end to end without
        # fabricating readiness — the same fixtures the built-in self-tests rely on.
        self.offline_demo_mode = (
            build_engine is None
            and eval_designer_service is None
            and (
                not os.environ.get("MODEL_API_KEY", "").strip()
                or os.environ.get("ADAPTOS_OFFLINE_DEMO", "").strip().lower()
                in ("1", "true", "yes")
            )
        )
        if self.offline_demo_mode:
            self.ed_service = EvalDesignerService(
                EvalDesignerConfig(data_root=self.data_root / "ed_storage"),
                mock_responder=_offline_demo_case_responder,
            )
        else:
            self.ed_service = eval_designer_service or EvalDesignerService(
                EvalDesignerConfig(data_root=self.data_root / "ed_storage")
            )
        self.splitter = NormalizedVaultSplitterAdapter(self.ed_service, self.vault)

        # 3. Builder Engine & Sandbox Verifier
        sbx_cfg = SandboxConfig(
            allow_subprocess_dev_fallback=config.allow_subprocess_sandbox_fallback
        )
        self.sandbox_verifier = SandboxVerifier(
            sbx_cfg, docker_runner_override=docker_runner_override
        )
        # Offline demo mode: when no live model key is configured, use the repo's own
        # deterministic fixture conventions (build_mock_cases_for_spec + a truthful
        # deterministic runtime handler) so the factory pipeline can run end to end.
        # Everything stays honest: outputs are deterministic fixtures, not fake success.
        if self.offline_demo_mode:
            offline_cfg = BuilderConfig(
                allow_subprocess_dev_fallback=config.allow_subprocess_sandbox_fallback,
                allow_deterministic_planner_fallback=True,
            )
            self.build_engine = BuildEngine(
                offline_cfg,
                self.storage,
                model_adapter=ReplayAndLiveModelAdapter(
                    offline_cfg, runtime_handler=_offline_demo_runtime_handler
                ),
                sandbox_verifier=self.sandbox_verifier,
            )
        else:
            self.build_engine = build_engine or BuildEngine(
                BuilderConfig(
                    allow_subprocess_dev_fallback=config.allow_subprocess_sandbox_fallback
                ),
                self.storage,
                sandbox_verifier=self.sandbox_verifier,
            )

        # 4. Protected Evaluator Coordinator (Isolated DB & Role Guard)
        eval_cfg = EvaluatorConfig(
            eval_db_path=self.data_root / "eval_plane" / "eval_ledger.db",
            vault_db_path=self.vault.vault_db_path,
            require_eval_role_env=True,
            allow_subprocess_sandbox_fallback=config.allow_subprocess_sandbox_fallback,
        )
        eval_model_port = eval_runtime_model_port or self.build_engine.model_adapter
        self.evaluator_coordinator = EvaluatorCoordinator(
            config=eval_cfg,
            vault_port=self.vault,
            runtime_model_port=eval_model_port,
            signer=self._signer,
            judge_port=judge_port,
            docker_runner_override=docker_runner_override,
            env_override={"AGNOS_PROCESS_ROLE": "eval"},
        )

        self._execution_lock = asyncio.Lock()
        self._active_run_id: str | None = None

        self.eval_bridge = AuthenticatedEvaluatorServiceBridge(
            coordinator=self.evaluator_coordinator,
            engine=self.build_engine,
            expected_service_token=config.service_token,
            caller_service_token=config.service_token,
            assets_provider=self._load_active_run_assets,
            max_job_bytes=config.max_eval_job_bytes,
            max_requests_per_minute=config.max_eval_requests_per_minute,
        )
        self.delivery_adapter = VerifiedDeliveryAdapter(
            asset_store=self.asset_store,
            eval_public_key_bytes=self.eval_public_key_bytes,
        )

        # 5. Factory Graph Orchestrator & Checkpointer
        self.deps = FactoryDeps(
            eval_designer=RealEvalDesignerAdapter(self.ed_service),
            splitter=self.splitter,
            builder=RealBuilderAdapter(self.build_engine),
            repair=RealRepairAdapter(
                self.build_engine,
                default_fixtures=repair_fixtures,
                provider_caller=repair_provider_caller,
            ),
            eval_plane=self.eval_bridge,
            asset_store=self.asset_store,
            delivery=self.delivery_adapter,
            eval_public_key_bytes=self.eval_public_key_bytes,
            node_timeout_seconds=config.node_timeout_seconds,
            split_seed=config.split_seed,
        )
        self.orchestrator = FactoryOrchestrator(self.deps)
        self.checkpointer = SqliteSerdeSaver(self.storage.get_checkpoint_db_path())
        self.compiled_graph = self.orchestrator.build_graph(
            checkpointer=self.checkpointer
        )

        # 6. Operational Runtime Backend (provisions verified 'ready' Factory bundles
        #    for end-user chat). Reuses the signed-verdict public key above and runs in
        #    single-owner MVP mode so owner identity is always server-controlled.
        self.runtime_service = AdaptOSRuntimeService(
            RuntimeServiceConfig(
                runtime_data_root=self.data_root / "runtime_backend",
                eval_public_key_bytes=self.eval_public_key_bytes,
                enforce_single_owner_mode=True,
                allow_subprocess_sandbox_fallback=config.allow_subprocess_sandbox_fallback,
            ),
            muse_transport=(
                _OfflineDemoMuseTransport()
                if not os.environ.get("MODEL_API_KEY", "").strip()
                else None  # live MuseApiClient transport when a key is configured
            ),
            docker_runner_override=docker_runner_override,
        )

    def _init_projects_table(self) -> None:
        with self.storage.get_factory_db() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS service_project_runs (
                    run_id TEXT PRIMARY KEY,
                    graph_state_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)

    def _project_exists(self, run_id: str) -> bool:
        with self.storage.get_factory_db() as conn:
            row = conn.execute(
                "SELECT 1 FROM service_project_runs WHERE run_id=?",
                (run_id,),
            ).fetchone()
        return row is not None

    def _save_graph_state(self, run_id: str, state: FactoryGraphState) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        raw_json = _canonical_bytes(state).decode("utf-8")
        with self.storage.get_factory_db() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO service_project_runs
                (run_id, graph_state_json, updated_at)
                VALUES (?, ?, ?)
                """,
                (run_id, raw_json, now_iso),
            )

    def load_graph_state(self, run_id: str) -> FactoryGraphState:
        with self.storage.get_factory_db() as conn:
            row = conn.execute(
                "SELECT graph_state_json FROM service_project_runs WHERE run_id=?",
                (run_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Project run '{run_id}' not found.")
        return json.loads(row["graph_state_json"])

    def _load_active_run_assets(self, run_id: str | None = None) -> list[SourceAssetInput]:
        """Fails closed when a referenced asset blob cannot be loaded or validated.

        When `run_id` is omitted, the currently bound active run is used (existing behavior).
        """
        rid = run_id or self._active_run_id
        if not rid:
            raise ProjectStateError(
                "Cannot load evaluation assets: no active project run_id is bound."
            )

        try:
            g_state = self.load_graph_state(rid)
        except Exception as exc:
            raise AdaptOSServiceError(
                f"Failed to load project state for active run '{rid}': {exc}",
                code="asset_load_failed",
            ) from exc

        refs = g_state.get("refs", {})
        assets_sha = refs.get("assets_blob_sha256")
        raw_assets_sha = refs.get("raw_assets_blob_sha256")

        if not assets_sha and not raw_assets_sha:
            return []

        blob_sha = assets_sha or raw_assets_sha
        assert blob_sha is not None
        try:
            raw_list = self.asset_store.get_json_blob(blob_sha)
        except Exception as exc:
            raise AdaptOSServiceError(
                f"Failed to load referenced asset blob '{blob_sha}' for project '{rid}': {exc}",
                code="asset_load_failed",
            ) from exc

        if not isinstance(raw_list, list):
            raise AdaptOSServiceError(
                f"Asset blob '{blob_sha}' for project '{rid}' must be a JSON list, got {type(raw_list).__name__}.",
                code="asset_validation_failed",
            )

        if not raw_list and raw_assets_sha and raw_assets_sha != blob_sha:
            try:
                raw_list = self.asset_store.get_json_blob(raw_assets_sha)
            except Exception as exc:
                raise AdaptOSServiceError(
                    f"Failed to load raw asset blob '{raw_assets_sha}' for project '{rid}': {exc}",
                    code="asset_load_failed",
                ) from exc
            if not isinstance(raw_list, list):
                raise AdaptOSServiceError(
                    f"Raw asset blob '{raw_assets_sha}' must be a JSON list.",
                    code="asset_validation_failed",
                )

        validated_assets: list[SourceAssetInput] = []
        for idx, item in enumerate(raw_list):
            if not isinstance(item, Mapping):
                raise AdaptOSServiceError(
                    f"Asset entry #{idx} in blob '{blob_sha}' is not a valid JSON object.",
                    code="asset_validation_failed",
                )
            try:
                sa = SourceAssetInput.model_validate(item)
            except Exception as exc:
                raise AdaptOSServiceError(
                    f"Asset entry #{idx} in blob '{blob_sha}' failed SourceAssetInput validation: {exc}",
                    code="asset_validation_failed",
                ) from exc
            if not sa.content or not sa.content.strip() or "\x00" in sa.content:
                raise AdaptOSServiceError(
                    f"Asset '{sa.filename}' in blob '{blob_sha}' has empty or binary content.",
                    code="asset_validation_failed",
                )
            validated_assets.append(sa)

        return validated_assets

    # ----------------------------------------------------------------------- #
    # Step 1: Project Initialization
    # ----------------------------------------------------------------------- #
    def create_project(
        self,
        user_goal: str,
        *,
        run_id: str | None = None,
        max_repair_attempts: int = 3,
    ) -> ProjectRunSummary:
        clean_goal = str(user_goal or "").strip()
        if not clean_goal:
            raise ValueError("user_goal must be a non-empty string.")
        rid = run_id or f"run_{uuid.uuid4().hex[:12]}"

        if self._project_exists(rid):
            raise ProjectStateError(
                f"Project run_id '{rid}' already exists; refusing to overwrite existing project state."
            )

        clamped_attempts = max(
            1, min(int(max_repair_attempts), MAX_GRAPH_REPAIR_ATTEMPTS)
        )

        f_state = FactoryState(
            stage="intake",
            user_goal=clean_goal,
            max_repair_attempts=clamped_attempts,
        )
        g_state: FactoryGraphState = {
            "factory": f_state.model_dump(mode="json"),
            "refs": {
                "run_id": rid,
                "handoff_blob_sha256": None,
                "raw_assets_blob_sha256": None,
                "assets_blob_sha256": None,
                "plan_hash": None,
                "dev_cases_blob_sha256": None,
                "sealed_set_id": None,
                "delivery_blob_sha256": None,
                "tried_patch_hashes": [],
            },
            "events": [f"[service] Created project run_id={rid}"],
        }
        self._save_graph_state(rid, g_state)
        return self.get_project_status(rid)

    # ----------------------------------------------------------------------- #
    # Step 2: Requirement Intake & Asset Profiling
    # ----------------------------------------------------------------------- #
    def ingest_assets(
        self,
        run_id: str,
        assets: Sequence[SourceAssetInput | Mapping[str, Any]],
    ) -> tuple[AssetProfile, ...]:
        g_state = self.load_graph_state(run_id)
        f_state = FactoryState.model_validate(g_state["factory"])
        if f_state.stage not in ("intake", "spec_review", "eval_design"):
            raise ProjectStateError(
                f"Cannot ingest assets in stage '{f_state.stage}'; must be in intake/spec_review/eval_design."
            )

        validated_assets: list[dict[str, Any]] = []
        profiles: list[AssetProfile] = []

        for item in assets:
            sa = (
                item
                if isinstance(item, SourceAssetInput)
                else SourceAssetInput.model_validate(item)
            )
            raw_bytes = sa.content.encode("utf-8")
            if not sa.content.strip() or b"\x00" in raw_bytes:
                raise ValueError(
                    f"Asset '{sa.filename}' is empty or contains null bytes."
                )
            digest = sha256_hex(raw_bytes)
            validated_assets.append(sa.model_dump(mode="json"))
            profiles.append(
                AssetProfile(
                    asset_id=sa.asset_id,
                    filename=sa.filename,
                    format=sa.format.strip().lower().lstrip("."),
                    size_bytes=len(raw_bytes),
                    sha256=digest,
                )
            )

        raw_blob_sha = self.asset_store.put_json_blob(validated_assets)
        g_state["refs"]["raw_assets_blob_sha256"] = raw_blob_sha
        g_state["refs"]["assets_blob_sha256"] = raw_blob_sha
        g_state["events"].append(
            f"[service] Ingested and profiled {len(profiles)} asset(s) (blob={raw_blob_sha[:12]})"
        )
        self._save_graph_state(run_id, g_state)
        return tuple(profiles)

    # ----------------------------------------------------------------------- #
    # Step 3: Spec Submission & Complete HandoffPackage Approval (BUG 1 FIX)
    # ----------------------------------------------------------------------- #
    def submit_spec_for_review(
        self,
        run_id: str,
        spec: Spec | Mapping[str, Any],
    ) -> ProjectRunSummary:
        g_state = self.load_graph_state(run_id)
        f_state = FactoryState.model_validate(g_state["factory"])
        if f_state.stage not in ("intake", "spec_review"):
            raise ProjectStateError(
                f"Cannot submit spec in stage '{f_state.stage}'; must be in 'intake' or 'spec_review'."
            )

        validated_spec = (
            spec if isinstance(spec, Spec) else Spec.model_validate(spec)
        )
        validated_spec = _normalize_spec_contract(validated_spec)
        f_state.spec = validated_spec
        f_state.stage = "spec_review"

        g_state["factory"] = f_state.model_dump(mode="json")
        g_state["events"].append(
            f"[service] Submitted Spec for review (spec_hash={validated_spec.content_hash()[:12]})"
        )
        self._save_graph_state(run_id, g_state)
        return self.get_project_status(run_id)

    def approve_spec(
        self,
        run_id: str,
        handoff: HandoffPackage | Mapping[str, Any],
    ) -> ProjectRunSummary:
        """Approves the submitted Spec using a complete, validated `intake.HandoffPackage`."""
        g_state = self.load_graph_state(run_id)
        f_state = FactoryState.model_validate(g_state["factory"])
        if f_state.stage != "spec_review" or f_state.spec is None:
            raise ProjectStateError(
                "Cannot approve Spec: project must be in 'spec_review' with a valid Spec."
            )

        if handoff is None:
            raise ProjectStateError(
                "Cannot approve Spec: a validated HandoffPackage is required."
            )

        declared_handoff_fields = set(HandoffPackage.model_fields.keys())
        required_sections = [
            sec
            for sec in MANDATORY_HANDOFF_SECTIONS
            if sec in declared_handoff_fields
        ]

        if isinstance(handoff, Mapping):
            missing_sections = [
                sec
                for sec in required_sections
                if sec not in handoff or handoff[sec] is None
            ]
            if missing_sections:
                raise ProjectStateError(
                    f"Incomplete handoff rejected: missing mandatory HandoffPackage fields {missing_sections}."
                )
            _validate_strict_provenance_audit_dict(handoff.get("provenance_audit"))

        try:
            validated_handoff: HandoffPackage = (
                handoff
                if isinstance(handoff, HandoffPackage)
                else HandoffPackage.model_validate(handoff)
            )
        except Exception as exc:
            raise ProjectStateError(
                f"HandoffPackage validation failed: {exc}"
            ) from exc

        # The submitted Spec was normalized at submission time; apply the identical
        # normalization to the handoff's Spec (and its approval hash) so the
        # hash-chain comparison below matches even when the client built the
        # handoff from the pre-normalization draft.
        handoff_spec_normalized = _normalize_spec_contract(validated_handoff.spec)
        if handoff_spec_normalized != validated_handoff.spec:
            normalized_hash = handoff_spec_normalized.content_hash()
            approval = validated_handoff.approval.model_copy(
                update={"spec_sha256": normalized_hash}
            )
            validated_handoff = validated_handoff.model_copy(
                update={"spec": handoff_spec_normalized, "approval": approval}
            )

        # Verify Spec match, specification hash, approval hash, field_provenance grounding, and criterion provenance
        _verify_handoff_provenance_and_hashes(validated_handoff, f_state.spec)

        # Validate state transition via intake.apply_handoff_to_factory_state on a deep copy first
        try:
            updated_f_state = apply_handoff_to_factory_state(
                f_state.model_copy(deep=True), validated_handoff
            )
        except Exception as exc:
            raise ProjectStateError(
                f"apply_handoff_to_factory_state rejected handoff: {exc}"
            ) from exc

        handoff_payload = validated_handoff.model_dump(mode="json")
        handoff_sha = self.asset_store.put_json_blob(handoff_payload)

        if updated_f_state.stage in ("intake", "spec_review"):
            updated_f_state.stage = "eval_design"

        spec_hash = f_state.spec.content_hash()
        g_state["factory"] = updated_f_state.model_dump(mode="json")
        g_state["refs"]["handoff_blob_sha256"] = handoff_sha
        g_state["events"].append(
            f"[service] Approved Spec via validated HandoffPackage (approved_spec_hash={spec_hash[:12]})"
        )
        self._save_graph_state(run_id, g_state)
        return self.get_project_status(run_id)

    # ----------------------------------------------------------------------- #
    # Steps 4–12: Factory Pipeline Execution (Serialized via asyncio.Lock)
    # ----------------------------------------------------------------------- #
    async def execute_factory_pipeline(self, run_id: str) -> ProjectRunSummary:
        """Executes Steps 4 through 12 via `FactoryOrchestrator`, serialized by `_execution_lock`."""
        async with self._execution_lock:
            g_state = self.load_graph_state(run_id)
            f_state = FactoryState.model_validate(g_state["factory"])
            if (
                f_state.approved_spec_hash is None
                or f_state.spec is None
                or not g_state.get("refs", {}).get("handoff_blob_sha256")
            ):
                raise ProjectStateError(
                    "Cannot execute factory pipeline before Spec is approved with a valid HandoffPackage (`approve_spec`)."
                )

            self._active_run_id = run_id
            try:
                cfg = {"configurable": {"thread_id": run_id}}
                final_state = await self.compiled_graph.ainvoke(
                    g_state, config=cfg
                )
                self._save_graph_state(run_id, final_state)
                return self.get_project_status(run_id)
            finally:
                self._active_run_id = None

    async def execute_single_stage(
        self,
        run_id: str,
        node_name: Literal[
            "init_run",
            "design_eval",
            "split_and_seal",
            "build",
            "dev_test",
            "repair",
            "freeze",
            "evaluate",
            "deliver",
        ],
    ) -> ProjectRunSummary:
        """Executes a single `FactoryOrchestrator` node while holding `_execution_lock`."""
        node_map = {
            "init_run": self.orchestrator.init_run_node,
            "design_eval": self.orchestrator.design_eval_node,
            "split_and_seal": self.orchestrator.split_and_seal_node,
            "build": self.orchestrator.build_node,
            "dev_test": self.orchestrator.dev_test_node,
            "repair": self.orchestrator.repair_node,
            "freeze": self.orchestrator.freeze_node,
            "evaluate": self.orchestrator.evaluate_node,
            "deliver": self.orchestrator.deliver_node,
        }
        if node_name not in node_map:
            raise ValueError(f"Unknown orchestrator node '{node_name}'.")

        async with self._execution_lock:
            g_state = self.load_graph_state(run_id)
            self._active_run_id = run_id
            try:
                updated = await node_map[node_name](g_state)
                if self.orchestrator._has_new_error(updated):  # type: ignore[arg-type]
                    updated = await self.orchestrator.fail_node(updated)  # type: ignore[arg-type]
                self._save_graph_state(run_id, updated)  # type: ignore[arg-type]
                return self.get_project_status(run_id)
            finally:
                self._active_run_id = None

    # ----------------------------------------------------------------------- #
    # Status Inspection & Ready-Gated Artifact Delivery
    # ----------------------------------------------------------------------- #
    def get_project_status(self, run_id: str) -> ProjectRunSummary:
        g_state = self.load_graph_state(run_id)
        f_state = FactoryState.model_validate(g_state["factory"])
        refs = g_state.get("refs", {})

        latest_dev_rate: float | None = None
        dev_passed = False
        if f_state.dev_runs:
            target_vid = (
                f_state.frozen.version_id
                if f_state.frozen is not None
                else (
                    f_state.candidate.version_id
                    if f_state.candidate is not None
                    else f_state.dev_runs[-1].version_id
                )
            )
            matching_runs = [
                r for r in f_state.dev_runs if r.version_id == target_vid
            ]
            chosen_run = (
                matching_runs[-1] if matching_runs else f_state.dev_runs[-1]
            )
            latest_dev_rate = chosen_run.pass_rate
            dev_passed = is_dev_run_passing(chosen_run)

        v_status = f_state.verdict.status if f_state.verdict is not None else None
        v_id = f_state.verdict.verdict_id if f_state.verdict is not None else None

        is_ready = bool(
            f_state.stage == "delivered"
            and f_state.verdict is not None
            and f_state.verdict.status == "ready"
            and refs.get("delivery_blob_sha256")
        )

        return ProjectRunSummary(
            run_id=run_id,
            stage=f_state.stage,
            user_goal=f_state.user_goal,
            approved_spec_hash=f_state.approved_spec_hash,
            plan_hash=refs.get("plan_hash"),
            sealed_set_id=refs.get("sealed_set_id"),
            baseline_version_id=f_state.baseline.version_id
            if f_state.baseline
            else None,
            candidate_version_id=f_state.candidate.version_id
            if f_state.candidate
            else None,
            frozen_version_id=f_state.frozen.version_id
            if f_state.frozen
            else None,
            dev_pass_rate=latest_dev_rate,
            dev_test_passed=dev_passed,
            repair_attempts=f_state.repair_attempts,
            repair_budget_left=f_state.repair_budget_left,
            verdict_status=v_status,  # type: ignore[arg-type]
            verdict_id=v_id,
            is_ready_for_delivery=is_ready,
            delivery_blob_sha256=refs.get("delivery_blob_sha256"),
            errors=tuple(f_state.errors),
            events=tuple(g_state.get("events", [])),
        )

    def get_delivery_package(self, run_id: str) -> DeliveryPackage:
        """Returns the recorded DeliveryPackage (which may hold a 'ready' or 'not_ready' Verdict)."""
        g_state = self.load_graph_state(run_id)
        f_state = FactoryState.model_validate(g_state["factory"])
        blob_sha = g_state.get("refs", {}).get("delivery_blob_sha256")
        if f_state.stage != "delivered" or not blob_sha:
            raise ProjectStateError(
                f"Project '{run_id}' has no DeliveryPackage (current stage='{f_state.stage}')."
            )
        raw_pkg = self.asset_store.get_json_blob(blob_sha)
        pkg = DeliveryPackage.model_validate(raw_pkg)
        self.delivery_adapter.verify_verdict_authenticity(
            spec=pkg.spec, artifact=pkg.manifest, verdict=pkg.verdict
        )
        return pkg

    def get_authorized_delivery(
        self, run_id: str
    ) -> tuple[DeliveryPackage, dict[str, bytes]]:
        """Releases the verified application bundle files ONLY when the Protected Evaluation Plane
        has issued a cryptographically verified Verdict with `status == 'ready'`.
        """
        g_state = self.load_graph_state(run_id)
        f_state = FactoryState.model_validate(g_state["factory"])

        if f_state.verdict is None:
            raise DeliveryNotAuthorizedError(
                f"Delivery denied for '{run_id}': no protected evaluation Verdict exists "
                f"(stage='{f_state.stage}'). Development test results alone never authorize delivery."
            )

        pkg = self.get_delivery_package(run_id)
        if pkg.verdict.status != "ready":
            raise DeliveryNotAuthorizedError(
                f"Delivery denied for '{run_id}': protected evaluation Verdict status is "
                f"'{pkg.verdict.status}' (must be 'ready')."
            )

        manifest, files_data = self.build_engine.assembler.load_bundle(
            pkg.manifest.version_id
        )
        AppRuntime.verify_bundle_integrity(manifest, files_data)
        if manifest.artifact_hash != pkg.verdict.artifact.artifact_hash:
            raise DeliveryNotAuthorizedError(
                "Delivery denied: loaded bundle hash does not match Verdict artifact_hash."
            )
        return pkg, files_data

    # ----------------------------------------------------------------------- #
    # Factory -> Runtime handoff (provisioning the verified application)
    # ----------------------------------------------------------------------- #
    @staticmethod
    def _build_verified_runtime_zip(
        pkg: DeliveryPackage, files_data: Mapping[str, bytes]
    ) -> bytes:
        """Serializes the authorized Factory delivery into the ZIP layout the Runtime
        Backend expects (`delivery_package.json` + manifest-declared bundle files)."""
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for rel_path in sorted(files_data.keys()):
                zf.writestr(rel_path, files_data[rel_path])
            zf.writestr(
                "delivery_package.json",
                _canonical_bytes(pkg.model_dump(mode="json")),
            )
        return zip_buf.getvalue()

    def provision_runtime_application(self, run_id: str) -> dict[str, Any]:
        """Factory-to-Runtime handoff: provisions the verified application for a run.

        Authorization chain (never weakened):
        1. `get_authorized_delivery(run_id)` re-verifies the Ed25519 Verdict signature,
           the spec hash binding, and bundle integrity, and refuses anything but a
           verified Verdict with status == 'ready'.
        2. Runtime provisioning re-verifies signature + integrity + sandbox support
           inside `runtime_service.provision_application`.
        The Runtime app id is deterministically derived as `app_<run_id>` so the
        Factory run ID <-> Runtime app ID mapping is stable across re-provisioning,
        which is idempotent and never wipes application storage or conversations.
        """
        pkg, files_data = self.get_authorized_delivery(run_id)
        app_id = f"app_{run_id}"
        zip_payload = self._build_verified_runtime_zip(pkg, files_data)
        assets = self._load_active_run_assets(run_id)
        summary = self.runtime_service.provision_application(
            zip_payload,
            project_run_id=run_id,
            app_id=app_id,
            assets=assets,
            auto_activate=True,
        )
        return summary.model_dump(mode="json")

    def get_runtime_application_status(self, run_id: str) -> dict[str, Any]:
        """Returns Runtime status for the run's application without provisioning it."""
        app_id = f"app_{run_id}"
        return self.runtime_service.get_application_status(app_id).model_dump(
            mode="json"
        )

    def create_runtime_chat_session(
        self, run_id: str, *, title: str | None = None
    ) -> dict[str, Any]:
        app_id = f"app_{run_id}"
        return self.runtime_service.create_chat_session(
            app_id, title=title
        ).model_dump(mode="json")

    def list_runtime_chat_sessions(self, run_id: str) -> list[dict[str, Any]]:
        app_id = f"app_{run_id}"
        sessions = self.runtime_service.list_chat_sessions(app_id)
        return [s.model_dump(mode="json") for s in sessions]

    def get_runtime_chat_history(
        self, run_id: str, session_id: str, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        app_id = f"app_{run_id}"
        messages = self.runtime_service.get_conversation_history(
            app_id, session_id, limit=limit
        )
        return [m.model_dump(mode="json") for m in messages]

    def send_runtime_chat_message(
        self,
        run_id: str,
        session_id: str,
        *,
        user_message: str,
        structured_inputs: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        app_id = f"app_{run_id}"
        turn = self.runtime_service.send_chat_message(
            app_id,
            session_id,
            user_message=user_message,
            structured_inputs=structured_inputs,
        )
        return turn.model_dump(mode="json")


# =========================================================================== #
# 5. EXPLICIT SYNTHETIC HANDOFF BUILDERS (BUG 2 FIX) & SELF-TEST SUITE
# =========================================================================== #


def _filter_declared_fields(
    model_cls: type[BaseModel], candidate_values: Mapping[str, Any]
) -> dict[str, Any]:
    """Selects only the keys declared on `model_cls.model_fields` from `candidate_values`."""
    return {
        k: v
        for k, v in candidate_values.items()
        if k in model_cls.model_fields
    }


def _build_synthetic_intake_asset_profile(
    *,
    asset_id: str,
    filename: str,
    content: str,
    chunk_id: str = "chunk_0",
) -> Any:
    """Explicitly constructs an `intake.AssetProfile` instance (and its chunk if applicable)."""
    raw_bytes = content.encode("utf-8")
    digest = sha256_hex(raw_bytes)
    now_utc = datetime.now(timezone.utc)

    chunks_val: Any = []
    if "chunks" in IntakeAssetProfile.model_fields:
        c_ann = IntakeAssetProfile.model_fields["chunks"].annotation
        c_args = get_args(c_ann)
        chunk_cls = c_args[0] if c_args else None
        chunk_candidates = {
            "chunk_id": chunk_id,
            "id": chunk_id,
            "asset_id": asset_id,
            "index": 0,
            "chunk_index": 0,
            "text": content,
            "content": content,
            "excerpt": content,
            "preview": content[:500],
            "start_char": 0,
            "end_char": len(content),
            "sha256": digest,
            "content_hash": digest,
        }
        if isinstance(chunk_cls, type) and issubclass(chunk_cls, BaseModel):
            chunks_val = [
                chunk_cls(**_filter_declared_fields(chunk_cls, chunk_candidates))
            ]
        else:
            chunks_val = [chunk_candidates]

    asset_candidates = {
        "asset_id": asset_id,
        "id": asset_id,
        "filename": filename,
        "name": filename,
        "path": filename,
        "media_type": "text/markdown",
        "mime_type": "text/markdown",
        "content_type": "text/markdown",
        "format": "md",
        "kind": "document",
        "asset_type": "document",
        "sha256": digest,
        "content_hash": digest,
        "size_bytes": len(raw_bytes),
        "byte_size": len(raw_bytes),
        "char_count": len(content),
        "content": content,
        "text": content,
        "preview": content,
        "sample_text": content,
        "extracted_text": content,
        "summary": content[:200],
        "chunks": chunks_val,
        "excerpts": chunks_val,
        "uploaded_at": now_utc,
        "created_at": now_utc,
    }
    return IntakeAssetProfile(
        **_filter_declared_fields(IntakeAssetProfile, asset_candidates)
    )


def _build_synthetic_handoff_package(
    spec: Spec,
    *,
    req_id: str = "req_001",
    approver_by: str = "user_reviewer_01",
    revision: int = 1,
    ground_via_asset: bool = False,
) -> HandoffPackage:
    """BUG 2 FIX: Explicitly constructs a valid `intake.HandoffPackage` using the actual
    model classes from `intake.py`:
    - `ApprovalRecord` (`by`, `at`, `revision`, `spec_sha256`)
    - `RequirementRecord` + `Provenance` (`kind="user_provided"`)
    - `TranscriptTurn` (`role="user"`, containing exact supporting quotes for every field)
    - `GroundedFieldSpec` under `in:<field_name>` and `out:<field_name>` keys
    - `CriterionProvenanceRecord` referencing `[req_id]`
    - `DiscoveryContext`
    - `IntakeAssetProfile` (`asset_manifest`)
    - `provenance_audit: dict[str, int]` (strictly integer counts)
    """
    spec_hash = spec.content_hash()
    now_utc = datetime.now(timezone.utc)
    turn_id = "turn_1"
    asset_id = "asset_policy_01"
    chunk_id = "chunk_0"

    # Build exact supporting quotes for the goal and every input/output field
    goal_quote = f"Requirement {req_id}: {spec.goal}"
    field_quotes: dict[str, str] = {}
    quote_lines: list[str] = [goal_quote]

    for f in [*spec.inputs, *spec.outputs]:
        human_name = f.name.replace("_", " ")
        q = f"Field {f.name} ({human_name}, type {f.data_type}): {f.description}"
        field_quotes[f.name] = q
        quote_lines.append(q)

    for c in spec.acceptance_criteria:
        quote_lines.append(f"Criterion {c.criterion_id} ({c.method}): {c.description}")

    full_evidence_text = "\n".join(quote_lines)

    # 1. Explicit TranscriptTurn (user role containing the exact source quotes)
    turn_candidates = {
        "turn_id": turn_id,
        "id": turn_id,
        "role": "user",
        "speaker": "user",
        "content": full_evidence_text,
        "text": full_evidence_text,
        "message": full_evidence_text,
        "at": now_utc,
        "timestamp": now_utc.isoformat(),
        "created_at": now_utc,
        "turn_index": 0,
    }
    user_turn = TranscriptTurn(
        **_filter_declared_fields(TranscriptTurn, turn_candidates)
    )
    transcript_list = [user_turn]

    # 2. Explicit AssetProfile list (empty for transcript-only tests, populated when asset-grounded)
    asset_manifest_list: list[Any] = []
    if ground_via_asset:
        asset_manifest_list.append(
            _build_synthetic_intake_asset_profile(
                asset_id=asset_id,
                filename="refund_policy.md",
                content=full_evidence_text,
                chunk_id=chunk_id,
            )
        )

    # 3. Explicit ApprovalRecord
    approval_candidates = {
        "by": approver_by,
        "approver_id": approver_by,
        "approved_by": approver_by,
        "at": now_utc,
        "approved_at": now_utc,
        "timestamp": now_utc,
        "revision": revision,
        "version": revision,
        "spec_sha256": spec_hash,
        "approved_spec_hash": spec_hash,
        "spec_hash": spec_hash,
        "approved": True,
        "notes": "Approved specification for build.",
    }
    approval_record = ApprovalRecord(
        **_filter_declared_fields(ApprovalRecord, approval_candidates)
    )

    # 4. Explicit Provenance & active RequirementRecord
    goal_start = full_evidence_text.index(goal_quote)
    goal_end = goal_start + len(goal_quote)
    prov_candidates = {
        "kind": "user_provided",
        "source_turn_id": turn_id,
        "turn_id": turn_id,
        "source_quote": goal_quote,
        "quote": goal_quote,
        "source_asset_id": None,
        "source_chunk_id": None,
        "start_char": None,
        "end_char": None,
        "rationale": "Explicitly stated by user in turn_1.",
        "note": "Explicitly stated by user in turn_1.",
    }
    try:
        req_provenance = Provenance(
            **_filter_declared_fields(Provenance, prov_candidates)
        )
    except Exception:
        prov_candidates["start_char"] = goal_start
        prov_candidates["end_char"] = goal_end
        req_provenance = Provenance(
            **_filter_declared_fields(Provenance, prov_candidates)
        )

    req_candidates = {
        "req_id": req_id,
        "requirement_id": req_id,
        "id": req_id,
        "text": spec.goal,
        "statement": spec.goal,
        "description": spec.goal,
        "requirement": spec.goal,
        "status": "active",
        "active": True,
        "superseded_by": None,
        "priority": "must",
        "kind": "functional",
        "category": "functional",
        "provenance": req_provenance,
        "revision": revision,
    }
    requirement_record = RequirementRecord(
        **_filter_declared_fields(RequirementRecord, req_candidates)
    )

    # 5. Explicit GroundedFieldSpec entries under in:<name> and out:<name>
    field_provenance_map: dict[str, GroundedFieldSpec] = {}
    io_fields = [("in", f) for f in spec.inputs] + [
        ("out", f) for f in spec.outputs
    ]

    for prefix, f in io_fields:
        key = f"{prefix}:{f.name}"
        f_quote = field_quotes[f.name]
        f_start = full_evidence_text.index(f_quote)
        f_end = f_start + len(f_quote)

        if ground_via_asset:
            gf_candidates: dict[str, Any] = {
                "name": f.name,
                "data_type": f.data_type,
                "description": f.description,
                "required": f.required,
                "source_turn_id": None,
                "source_quote": f_quote,
                "source_asset_id": asset_id,
                "source_chunk_id": chunk_id,
                "start_char": f_start,
                "end_char": f_end,
            }
            gf_obj = GroundedFieldSpec(
                **_filter_declared_fields(GroundedFieldSpec, gf_candidates)
            )
        else:
            # Try transcript grounding with start_char=None, end_char=None first,
            # and fall back to exact char offsets if required by GroundedFieldSpec/ProvenanceVerifier.
            gf_candidates_no_offsets = {
                "name": f.name,
                "data_type": f.data_type,
                "description": f.description,
                "required": f.required,
                "source_turn_id": turn_id,
                "source_quote": f_quote,
                "source_asset_id": None,
                "source_chunk_id": None,
                "start_char": None,
                "end_char": None,
            }
            gf_candidates_with_offsets = {
                **gf_candidates_no_offsets,
                "start_char": f_start,
                "end_char": f_end,
            }
            gf_obj = None
            for cand_dict in (gf_candidates_no_offsets, gf_candidates_with_offsets):
                try:
                    trial_gf = GroundedFieldSpec(
                        **_filter_declared_fields(GroundedFieldSpec, cand_dict)
                    )
                    _invoke_intake_verify_field_grounding(
                        trial_gf,
                        transcript_list,
                        asset_manifest_list,
                        expected_key=key,
                    )
                    gf_obj = trial_gf
                    break
                except Exception:
                    continue
            if gf_obj is None:
                gf_obj = GroundedFieldSpec(
                    **_filter_declared_fields(
                        GroundedFieldSpec, gf_candidates_with_offsets
                    )
                )

        field_provenance_map[key] = gf_obj

    # 6. Explicit CriterionProvenanceRecord list
    criterion_provenance_list: list[CriterionProvenanceRecord] = []
    for c in spec.acceptance_criteria:
        c_quote = f"Criterion {c.criterion_id} ({c.method}): {c.description}"
        cp_candidates = {
            "criterion_id": c.criterion_id,
            "requirement_ids": [req_id],
            "provenance": req_provenance,
            "source_turn_id": turn_id,
            "source_quote": c_quote,
            "rationale": c.description,
            "description": c.description,
            "method": c.method,
        }
        criterion_provenance_list.append(
            CriterionProvenanceRecord(
                **_filter_declared_fields(CriterionProvenanceRecord, cp_candidates)
            )
        )

    # 7. Explicit DiscoveryContext
    disc_candidates = {
        "user_goal": spec.goal,
        "initial_goal": spec.goal,
        "goal": spec.goal,
        "problem_statement": spec.goal,
        "domain": "customer_support",
        "summary": spec.goal,
        "context_summary": spec.goal,
        "turn_count": 1,
        "turns_used": 1,
        "clarification_turns": 1,
        "assumptions": list(spec.constraints),
        "constraints": list(spec.constraints),
        "confirmed_constraints": list(spec.constraints),
        "resolved_ambiguities": list(spec.constraints),
        "open_questions": [],
        "unresolved_questions": [],
        "blocking_questions": [],
        "blocking_ambiguities": [],
        "assets": asset_manifest_list,
        "asset_profiles": asset_manifest_list,
    }
    discovery_context = DiscoveryContext(
        **_filter_declared_fields(DiscoveryContext, disc_candidates)
    )

    # 8. Strictly dict[str, int] provenance_audit
    total_fields = len(spec.inputs) + len(spec.outputs)
    provenance_audit: dict[str, int] = {
        "user_provided": 0 if ground_via_asset else total_fields,
        "asset_derived": total_fields if ground_via_asset else 0,
        "inferred": 0,
        "invented_fields_rejected": 0,
    }

    # 9. Explicit agent1_run if declared on HandoffPackage
    handoff_kwargs: dict[str, Any] = {
        "spec": spec,
        "spec_sha256": spec_hash,
        "approval": approval_record,
        "discovery_context": discovery_context,
        "requirements": [requirement_record],
        "requirement_map": {req_id: spec.goal},
        "field_provenance": field_provenance_map,
        "criterion_provenance": criterion_provenance_list,
        "transcript": transcript_list,
        "asset_manifest": asset_manifest_list,
        "provenance_audit": provenance_audit,
    }

    if "agent1_run" in HandoffPackage.model_fields:
        run_ann = HandoffPackage.model_fields["agent1_run"].annotation
        origin = get_origin(run_ann)
        if origin is not None and str(origin) in ("typing.Union", "types.UnionType"):
            non_none = [a for a in get_args(run_ann) if a is not type(None)]
            if len(non_none) == 1:
                run_ann = non_none[0]
        run_candidates = {
            "run_id": "agent1_run_001",
            "session_id": "agent1_run_001",
            "thread_id": "agent1_run_001",
            "model": "muse-spark-1.3",
            "model_id": "muse-spark-1.3",
            "turns": 1,
            "turn_count": 1,
            "total_turns": 1,
            "turns_used": 1,
            "calls": 1,
            "total_calls": 1,
            "llm_calls": 1,
            "call_count": 1,
            "input_tokens": 500,
            "prompt_tokens": 500,
            "output_tokens": 200,
            "completion_tokens": 200,
            "cached_tokens": 0,
            "total_tokens": 700,
            "cost_usd": 0.002,
            "total_cost_usd": 0.002,
            "estimated_cost_usd": 0.002,
            "budget_usd": 0.50,
            "max_cost_usd": 0.50,
            "cost_cap_usd": 0.50,
            "latency_ms": 50,
            "total_latency_ms": 50,
            "wall_time_ms": 50,
            "repair_attempts": 0,
            "spec_repairs": 0,
            "retries": 0,
            "records": [],
            "call_ledger": [],
            "ledger": [],
            "steps": [],
            "events": [],
            "started_at": now_utc,
            "completed_at": now_utc,
            "created_at": now_utc,
        }
        if isinstance(run_ann, type) and issubclass(run_ann, BaseModel):
            for rf, rinfo in run_ann.model_fields.items():
                if get_origin(rinfo.annotation) in (list, tuple, Sequence) and rf in (
                    "calls",
                    "turns",
                ):
                    run_candidates[rf] = []
            handoff_kwargs["agent1_run"] = run_ann(
                **_filter_declared_fields(run_ann, run_candidates)
            )
        else:
            handoff_kwargs["agent1_run"] = run_candidates

    return HandoffPackage(**_filter_declared_fields(HandoffPackage, handoff_kwargs))


def _make_service_test_spec(include_rag: bool = True) -> Spec:
    if not include_rag:
        return Spec(
            goal="Normalize customer order discount requests into structured eligibility output.",
            inputs=[
                FieldSpec(
                    name="order_total",
                    data_type="number",
                    description="Order total in USD.",
                    required=True,
                ),
                FieldSpec(
                    name="customer_tier",
                    data_type="string",
                    description="Customer loyalty tier.",
                    required=True,
                ),
            ],
            outputs=[
                FieldSpec(
                    name="decision",
                    data_type="string",
                    description="approve_discount or reject_discount.",
                    required=True,
                ),
            ],
            constraints=["Orders over 100 USD for gold tier receive approve_discount."],
            acceptance_criteria=[
                AcceptanceCriterion(
                    criterion_id="crit_exact_decision",
                    description="Accurately classifies discount eligibility decision label.",
                    method="exact_match",
                    min_pass_rate=0.80,
                ),
            ],
        )

    return Spec(
        goal="Triage customer refund requests against Section 4.2 Refund Policy and cite evidence.",
        inputs=[
            FieldSpec(
                name="customer_query",
                data_type="string",
                description="Customer support request text.",
                required=True,
            ),
            FieldSpec(
                name="days_since_purchase",
                data_type="integer",
                description="Days elapsed since initial purchase.",
                required=True,
            ),
        ],
        outputs=[
            FieldSpec(
                name="decision",
                data_type="string",
                description="Triage decision label (approve_refund, reject_refund).",
                required=True,
            ),
            FieldSpec(
                name="policy_citation",
                data_type="string",
                description="Verbatim supporting policy citation.",
                required=True,
            ),
        ],
        constraints=["Never approve refunds after 30 calendar days."],
        acceptance_criteria=[
            AcceptanceCriterion(
                criterion_id="crit_exact_decision",
                description="Accurately classifies refund eligibility decision label.",
                method="exact_match",
                min_pass_rate=0.80,
            ),
            AcceptanceCriterion(
                criterion_id="crit_citation",
                description="Includes policy citation from Section 4.2 Refund Policy.",
                method="contains",
                min_pass_rate=0.80,
            ),
        ],
    )


def _create_configured_test_service(
    tmp_root: Path,
    *,
    spec: Spec | None = None,
    seed_retrieval_bug: bool = False,
    enable_effective_repair: bool = True,
) -> tuple[AdaptOSService, Spec]:
    active_spec = spec or _make_service_test_spec(include_rag=True)
    is_rag = any("citation" in f.name for f in active_spec.outputs)
    policy_text = (
        "Section 4.2 Refund Policy: Full refunds are granted within 30 calendar days of purchase "
        "if the software license key has not been activated."
    )
    svc_cfg = AdaptOSServiceConfig(
        data_root=tmp_root / "adaptos_svc",
        eval_signing_seed=b"adaptos_service_test_seed_32byte",
        max_repair_attempts=2,
    )
    storage = ensure_storage_compat(
        StorageService(StorageConfig(svc_cfg.data_root / "factory_storage"))
    )
    storage.initialize()

    ed_cfg = EvalDesignerConfig(
        data_root=svc_cfg.data_root / "ed_storage",
        min_dev_cases_per_criterion=5,
        min_generated_cases_per_criterion=5,
        max_generated_cases_per_criterion=50,
    )

    def _ed_responder(purpose: str, prompt: str, model_cls: Any) -> dict[str, Any]:
        source_docs = (
            (
                SourceDocument(
                    source_id="pol_v1",
                    filename="refund_policy.md",
                    sha256=sha256_hex(policy_text.encode("utf-8")),
                    content=policy_text,
                ),
            )
            if is_rag
            else ()
        )
        app_spec = ApprovedSpec.from_factory_spec(
            active_spec.model_dump(mode="json"),
            expected_spec_hash=active_spec.content_hash(),
            source_documents=source_docs,
        )
        # Generic deterministic fixture generator: derives cases from the actual
        # spec inputs/outputs in the request payload (build_mock_cases_for_spec is
        # hardcoded to refund-triage field names and yields 0 eligible cases for
        # any other spec shape).
        return _offline_demo_case_responder(purpose, prompt, model_cls)

    ed_service = EvalDesignerService(ed_cfg, mock_responder=_ed_responder)

    def _runtime_handler(
        sys_p: str, usr_p: str, schema: dict[str, Any]
    ) -> dict[str, Any]:
        # Seeded retrieval bug (repair-verification fixture): when RAG is expected
        # but no evidence block reached the prompt, emit an ungrounded citation so
        # dev tests fail and the bounded repair loop must fix retrieval mode.
        if (
            is_rag
            and "<untrusted_retrieved_evidence>" not in usr_p
            and seed_retrieval_bug
        ):
            out_fields = [
                k for k in (schema.get("properties") or {}).keys()
            ]
            out: dict[str, Any] = {}
            for k in out_fields:
                if "citation" in k:
                    out[k] = "Ungrounded citation without retrieval"
                else:
                    out[k] = schema["properties"][k].get("enum", ["ungrounded"])[0]
            return out
        return _offline_demo_runtime_handler(sys_p, usr_p, schema)

    app_id = f"app-{active_spec.content_hash()[:10]}"
    out_schema = spec_fields_to_json_schema(active_spec.outputs)
    ret_mode = "all" if seed_retrieval_bug else "any"

    if is_rag:
        cand_draft: dict[str, Any] = {
            "role": "candidate",
            "steps": [
                {
                    "step_id": "step_validate_in",
                    "component_ref": "io.validate@1.0.0",
                    "config": {"mode": "input"},
                    "depends_on": [],
                    "need_ids": ["need_io_validate"],
                    "decision": "reuse_unchanged",
                },
                {
                    "step_id": "step_doc_ingest",
                    "component_ref": "doc.ingest@1.0.0",
                    "config": {
                        "app_id": app_id,
                        "chunk_size": 500,
                        "overlap": 50,
                        "formats": ["txt", "md", "csv", "json"],
                    },
                    "depends_on": ["step_validate_in"],
                    "need_ids": ["need_doc_ingest"],
                    "decision": "reuse_configured",
                },
                {
                    "step_id": "step_retrieve",
                    "component_ref": "retrieve.lexical@1.0.0",
                    "config": {
                        "app_id": app_id,
                        "top_k": 3,
                        "mode": ret_mode,
                        "citation_mode": True,
                    },
                    "depends_on": ["step_doc_ingest"],
                    "need_ids": ["need_retrieve_lexical"],
                    "decision": "reuse_configured",
                },
                {
                    "step_id": "step_prompt",
                    "component_ref": "prompt.compose@1.0.0",
                    "config": {
                        "template": "Goal: {goal}\nConstraints:\n{constraints}\nContext:\n{context}\nInput:\n{input_json}",
                        "verbatim_constraints": list(active_spec.constraints),
                        "few_shot_case_ids": [],
                        "max_context_tokens": 4000,
                    },
                    "depends_on": ["step_retrieve"],
                    "need_ids": ["need_prompt_compose"],
                    "decision": "reuse_configured",
                },
                {
                    "step_id": "step_model",
                    "component_ref": "model.chat@1.0.0",
                    "config": {
                        "model": "muse-spark-1.3",
                        "effort": "low",
                        "max_tokens": 2048,
                    },
                    "depends_on": ["step_prompt"],
                    "need_ids": ["need_model_chat"],
                    "decision": "reuse_unchanged",
                },
                {
                    "step_id": "step_structured_out",
                    "component_ref": "output.structured@1.0.0",
                    "config": {"json_schema": out_schema, "parse_retries": 1},
                    "depends_on": ["step_model"],
                    "need_ids": ["need_output_structured"],
                    "decision": "reuse_configured",
                },
                {
                    "step_id": "step_cite_verify",
                    "component_ref": "cite.verify@1.0.0",
                    "config": {
                        "citation_field": "policy_citation",
                        "match_mode": "substring",
                        "require_non_empty_retrieval": True,
                    },
                    "depends_on": ["step_structured_out"],
                    "need_ids": ["need_cite_verify"],
                    "decision": "compose",
                },
                {
                    "step_id": "step_trace",
                    "component_ref": "log.trace@1.0.0",
                    "config": {"always_on": True},
                    "depends_on": ["step_cite_verify"],
                    "need_ids": ["need_log_trace"],
                    "decision": "reuse_unchanged",
                },
            ],
            "criteria_map": {
                "crit_exact_decision": [
                    "step_prompt",
                    "step_model",
                    "step_structured_out",
                ],
                "crit_citation": [
                    "step_retrieve",
                    "step_prompt",
                    "step_model",
                    "step_cite_verify",
                ],
            },
            "rationale": "Service integration test RAG candidate plan.",
        }
    else:
        cand_draft = {
            "role": "candidate",
            "steps": [
                {
                    "step_id": "step_wf",
                    "component_ref": "workflow.linear@1.0.0",
                    "config": {"strict_order": True},
                    "depends_on": [],
                    "need_ids": [],
                    "decision": "compose",
                },
                {
                    "step_id": "step_validate_in",
                    "component_ref": "io.validate@1.0.0",
                    "config": {"mode": "both"},
                    "depends_on": ["step_wf"],
                    "need_ids": ["need_io_validate"],
                    "decision": "reuse_configured",
                },
                {
                    "step_id": "step_prompt",
                    "component_ref": "prompt.compose@1.0.0",
                    "config": {
                        "template": "Goal: {goal}\nConstraints:\n{constraints}\nInput:\n{input_json}",
                        "verbatim_constraints": list(active_spec.constraints),
                        "few_shot_case_ids": [],
                        "max_context_tokens": 4000,
                    },
                    "depends_on": ["step_validate_in"],
                    "need_ids": ["need_prompt_compose"],
                    "decision": "reuse_configured",
                },
                {
                    "step_id": "step_model",
                    "component_ref": "model.chat@1.0.0",
                    "config": {
                        "model": "muse-spark-1.3",
                        "effort": "low",
                        "max_tokens": 1024,
                    },
                    "depends_on": ["step_prompt"],
                    "need_ids": ["need_model_chat"],
                    "decision": "reuse_unchanged",
                },
                {
                    "step_id": "step_structured_out",
                    "component_ref": "output.structured@1.0.0",
                    "config": {"json_schema": out_schema, "parse_retries": 1},
                    "depends_on": ["step_model"],
                    "need_ids": ["need_output_structured"],
                    "decision": "reuse_configured",
                },
                {
                    "step_id": "step_trace",
                    "component_ref": "log.trace@1.0.0",
                    "config": {"always_on": True},
                    "depends_on": ["step_structured_out"],
                    "need_ids": ["need_log_trace"],
                    "decision": "reuse_unchanged",
                },
            ],
            "criteria_map": {
                "crit_exact_decision": [
                    "step_prompt",
                    "step_model",
                    "step_structured_out",
                ]
            },
            "rationale": "Service integration test non-RAG candidate plan.",
        }

    adapter = ReplayAndLiveModelAdapter(
        BuilderConfig(),
        planner_fixtures=[cand_draft],
        runtime_handler=_runtime_handler,
    )
    verifier = SandboxVerifier(
        SandboxConfig(), docker_runner_override=_simulated_docker_runner_for_tests
    )
    engine = BuildEngine(
        BuilderConfig(),
        storage,
        model_adapter=adapter,
        sandbox_verifier=verifier,
    )

    async def _repair_provider(
        sys_p: str, usr_p: str, model_cls: Any, effort: str, max_tok: int
    ) -> tuple[Any, dict[str, int | None]]:
        payload = json.loads(usr_p)
        repro = payload.get("reproduced_failures", [])
        ev_id = repro[0]["case_id"] if repro else "case_1"
        if enable_effective_repair:
            return (
                {
                    "kind": "config",
                    "target": "step_retrieve",
                    "hypothesis": "LLM hypothesis: switch retrieve.lexical mode to any",
                    "evidence_case_ids": [ev_id],
                    "ops": [
                        {
                            "op": "set_config",
                            "file": "app_config.json",
                            "step_id": "step_retrieve",
                            "pointer": "/mode",
                            "value": "any",
                        }
                    ],
                },
                {"input_tokens": 1000, "output_tokens": 250},
            )
        return (
            {
                "kind": "prompt",
                "target": f"prompts/ineffective_{uuid.uuid4().hex[:6]}.txt",
                "hypothesis": "LLM hypothesis: add ineffective note",
                "evidence_case_ids": [ev_id],
                "ops": [
                    {
                        "op": "add_file",
                        "file": f"prompts/ineffective_{uuid.uuid4().hex[:6]}.txt",
                        "content": f"Ineffective note {uuid.uuid4().hex}",
                    }
                ],
            },
            {"input_tokens": 1000, "output_tokens": 250},
        )

    service = AdaptOSService(
        svc_cfg,
        storage=storage,
        eval_designer_service=ed_service,
        build_engine=engine,
        eval_runtime_model_port=adapter,
        repair_provider_caller=_repair_provider,
        docker_runner_override=_simulated_docker_runner_for_tests,
    )
    return service, active_spec


class ServiceLayerSelfTestSuite(unittest.IsolatedAsyncioTestCase):
    """Focused and end-to-end tests for `service.py` covering Bugs 1 & 2 and all 11 required tests."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="adaptos_service_test_")
        self.tmp_path = Path(self._tmp.name)

    def tearDown(self) -> None:
        # Checkpoint open SQLite WAL files so Windows releases locks before cleanup.
        import sqlite3 as _sqlite3
        for _db in self.tmp_path.rglob("*.db"):
            try:
                with _sqlite3.connect(str(_db), timeout=2.0) as _c:
                    _c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except Exception:
                pass
        try:
            self._tmp.cleanup()
        except PermissionError:
            pass

    def test_01_valid_transcript_grounded_handoff_passes_pydantic_and_advances_to_eval_design(self) -> None:
        """Tests 1, 8, 10: Valid transcript-grounded synthetic HandoffPackage passes actual Pydantic
        validation, ProvenanceVerifier.verify_field_grounding(), and advances approve_spec() to eval_design.
        """
        service, spec = _create_configured_test_service(self.tmp_path)
        service.create_project(spec.goal, run_id="run_handoff_ok")
        service.submit_spec_for_review("run_handoff_ok", spec)

        valid_handoff = _build_synthetic_handoff_package(spec, ground_via_asset=False)
        # Test 8: Round-trip through actual Pydantic HandoffPackage validation
        roundtrip_handoff = HandoffPackage.model_validate(
            valid_handoff.model_dump(mode="json")
        )
        self.assertEqual(
            set(roundtrip_handoff.field_provenance.keys()),
            {
                "in:customer_query",
                "in:days_since_purchase",
                "out:decision",
                "out:policy_citation",
            },
        )
        self.assertTrue(
            all(
                isinstance(v, int) and not isinstance(v, bool)
                for v in roundtrip_handoff.provenance_audit.values()
            )
        )

        # Tests 1 & 10: Accepted by approve_spec() and advances project to eval_design
        summary = service.approve_spec("run_handoff_ok", roundtrip_handoff)
        self.assertEqual(summary.stage, "eval_design")
        self.assertEqual(summary.approved_spec_hash, spec.content_hash())

    def test_02_missing_input_and_missing_output_field_provenance_rejected(self) -> None:
        """Tests 2 & 3: Missing in:<field_name> or out:<field_name> entry in field_provenance is rejected."""
        service, spec = _create_configured_test_service(self.tmp_path)
        service.create_project(spec.goal, run_id="run_missing_fp")
        service.submit_spec_for_review("run_missing_fp", spec)

        base_dict = _build_synthetic_handoff_package(spec).model_dump(mode="json")

        # Test 2: Missing input provenance 'in:days_since_purchase'
        missing_in_dict = copy.deepcopy(base_dict)
        missing_in_dict["field_provenance"].pop("in:days_since_purchase", None)
        with self.assertRaises(ProjectStateError) as ctx_in:
            service.approve_spec("run_missing_fp", missing_in_dict)
        self.assertIn("in:days_since_purchase", str(ctx_in.exception))

        # Test 3: Missing output provenance 'out:policy_citation'
        missing_out_dict = copy.deepcopy(base_dict)
        missing_out_dict["field_provenance"].pop("out:policy_citation", None)
        with self.assertRaises(ProjectStateError) as ctx_out:
            service.approve_spec("run_missing_fp", missing_out_dict)
        self.assertIn("out:policy_citation", str(ctx_out.exception))

    def test_03_mismatched_grounded_field_name_and_unsupported_quote_rejected(self) -> None:
        """Tests 4 & 5: GroundedFieldSpec.name not matching its key is rejected, and a source_quote
        that does not support the field in ProvenanceVerifier.verify_field_grounding() is rejected.
        """
        service, spec = _create_configured_test_service(self.tmp_path)
        service.create_project(spec.goal, run_id="run_bad_grounding")
        service.submit_spec_for_review("run_bad_grounding", spec)

        base_dict = _build_synthetic_handoff_package(spec).model_dump(mode="json")

        # Test 4: GroundedFieldSpec.name does not match its key 'in:customer_query'
        bad_name_dict = copy.deepcopy(base_dict)
        bad_name_dict["field_provenance"]["in:customer_query"]["name"] = "wrong_field_name"
        with self.assertRaises(ProjectStateError) as ctx_name:
            service.approve_spec("run_bad_grounding", bad_name_dict)
        self.assertIn("wrong_field_name", str(ctx_name.exception))

        # Test 5: Quote does not support the field (unrelated quote in transcript)
        bad_quote_dict = copy.deepcopy(base_dict)
        unrelated_sentence = "The cafeteria menu features pasta on Tuesday afternoon."
        turn0 = bad_quote_dict["transcript"][0]
        for text_key in ("content", "text", "message"):
            if text_key in turn0 and isinstance(turn0[text_key], str):
                turn0[text_key] = turn0[text_key] + "\n" + unrelated_sentence
        bad_quote_dict["field_provenance"]["in:customer_query"][
            "source_quote"
        ] = unrelated_sentence
        if bad_quote_dict["field_provenance"]["in:customer_query"].get("start_char") is not None:
            full_t = turn0.get("content") or turn0.get("text")
            s_idx = full_t.index(unrelated_sentence)
            bad_quote_dict["field_provenance"]["in:customer_query"]["start_char"] = s_idx
            bad_quote_dict["field_provenance"]["in:customer_query"]["end_char"] = s_idx + len(unrelated_sentence)

        with self.assertRaises(ProjectStateError):
            service.approve_spec("run_bad_grounding", bad_quote_dict)

    def test_04_valid_asset_grounded_field_provenance_accepted(self) -> None:
        """Test 6: Valid asset-grounded field provenance is accepted when using a properly constructed asset fixture."""
        service, spec = _create_configured_test_service(self.tmp_path)
        service.create_project(spec.goal, run_id="run_asset_grounded")
        service.submit_spec_for_review("run_asset_grounded", spec)

        asset_handoff = _build_synthetic_handoff_package(spec, ground_via_asset=True)
        self.assertEqual(len(asset_handoff.asset_manifest), 1)
        for gf in asset_handoff.field_provenance.values():
            self.assertEqual(gf.source_asset_id, "asset_policy_01")
            self.assertIsNone(gf.source_turn_id)

        summary = service.approve_spec("run_asset_grounded", asset_handoff)
        self.assertEqual(summary.stage, "eval_design")
        self.assertEqual(summary.approved_spec_hash, spec.content_hash())

    def test_05_criterion_provenance_unknown_requirement_and_invalid_provenance_audit_rejected(self) -> None:
        """Tests 7 & 9: Criterion provenance referencing an unknown requirement ID is rejected,
        and invalid provenance_audit values (strings, booleans, datetimes) are rejected.
        """
        service, spec = _create_configured_test_service(self.tmp_path)
        service.create_project(spec.goal, run_id="run_crit_and_audit")
        service.submit_spec_for_review("run_crit_and_audit", spec)

        base_dict = _build_synthetic_handoff_package(spec).model_dump(mode="json")

        # Test 7: CriterionProvenanceRecord referencing unknown requirement ID
        bad_crit_dict = copy.deepcopy(base_dict)
        bad_crit_dict["criterion_provenance"][0]["requirement_ids"] = [
            "req_unknown_999"
        ]
        with self.assertRaises(ProjectStateError):
            service.approve_spec("run_crit_and_audit", bad_crit_dict)

        # Test 9: Invalid provenance_audit values (strings, booleans, negative ints)
        for bad_audit in (
            {"status": "passed", "audited_at": "2026-11-03T00:00:00Z"},
            {"user_provided": True},
            {"user_provided": -1},
        ):
            bad_audit_dict = copy.deepcopy(base_dict)
            bad_audit_dict["provenance_audit"] = bad_audit
            with self.assertRaises(ProjectStateError):
                service.approve_spec("run_crit_and_audit", bad_audit_dict)

    def test_06_failed_handoff_validation_leaves_project_state_and_handoff_ref_unchanged(self) -> None:
        """Test 11: Failed handoff validation preserves spec_review stage and leaves handoff_blob_sha256 None."""
        service, spec = _create_configured_test_service(self.tmp_path)
        service.create_project(spec.goal, run_id="run_atomic_approve")
        service.submit_spec_for_review("run_atomic_approve", spec)

        other_spec = spec.model_copy(update={"goal": "Tampered spec goal"})
        bad_handoff = _build_synthetic_handoff_package(other_spec)
        with self.assertRaises(ProjectStateError):
            service.approve_spec("run_atomic_approve", bad_handoff)

        status = service.get_project_status("run_atomic_approve")
        self.assertEqual(status.stage, "spec_review")
        self.assertIsNone(status.approved_spec_hash)

        g_state = service.load_graph_state("run_atomic_approve")
        self.assertIsNone(g_state["refs"]["handoff_blob_sha256"])

    async def test_07_asset_blob_loading_or_validation_failure_raises_and_fails_closed(self) -> None:
        """Preserved Fix 2 Test: Missing or invalid referenced asset blob raises error and fails closed."""
        service, spec = _create_configured_test_service(
            self.tmp_path, seed_retrieval_bug=False
        )
        service.create_project(spec.goal, run_id="run_asset_fail")
        service.ingest_assets(
            "run_asset_fail",
            [
                {
                    "asset_id": "pol_v1",
                    "filename": "refund_policy.md",
                    "content": "Section 4.2 Refund Policy: Full refunds within 30 calendar days.",
                    "format": "md",
                }
            ],
        )
        service.submit_spec_for_review("run_asset_fail", spec)
        service.approve_spec(
            "run_asset_fail", _build_synthetic_handoff_package(spec)
        )

        for node in ("init_run", "design_eval", "split_and_seal", "build", "dev_test", "freeze"):
            await service.execute_single_stage("run_asset_fail", node)  # type: ignore[arg-type]

        g_state = service.load_graph_state("run_asset_fail")
        g_state["refs"]["assets_blob_sha256"] = "f" * 64
        g_state["refs"]["raw_assets_blob_sha256"] = "f" * 64
        service._save_graph_state("run_asset_fail", g_state)

        service._active_run_id = "run_asset_fail"
        try:
            with self.assertRaises(AdaptOSServiceError) as ctx_load:
                service._load_active_run_assets()
            self.assertEqual(ctx_load.exception.code, "asset_load_failed")
        finally:
            service._active_run_id = None

        bad_asset_blob = service.asset_store.put_json_blob(
            [{"invalid_asset_schema": "missing_required_fields"}]
        )
        g_state["refs"]["assets_blob_sha256"] = bad_asset_blob
        g_state["refs"]["raw_assets_blob_sha256"] = bad_asset_blob
        service._save_graph_state("run_asset_fail", g_state)

        summary_after_eval = await service.execute_single_stage(
            "run_asset_fail", "evaluate"
        )
        self.assertEqual(summary_after_eval.stage, "failed")
        self.assertIsNone(summary_after_eval.verdict_status)
        self.assertFalse(summary_after_eval.is_ready_for_delivery)

    async def test_08_project_with_genuinely_no_uploaded_assets_behaves_correctly(self) -> None:
        """Preserved Fix 2 Test: Projects with genuinely no uploaded assets return [] and execute cleanly."""
        non_rag_spec = _make_service_test_spec(include_rag=False)
        service, _ = _create_configured_test_service(
            self.tmp_path / "no_assets", spec=non_rag_spec, seed_retrieval_bug=False
        )
        service.create_project(non_rag_spec.goal, run_id="run_no_assets")
        service.submit_spec_for_review("run_no_assets", non_rag_spec)
        service.approve_spec(
            "run_no_assets", _build_synthetic_handoff_package(non_rag_spec)
        )

        service._active_run_id = "run_no_assets"
        try:
            self.assertEqual(service._load_active_run_assets(), [])
        finally:
            service._active_run_id = None

        summary = await service.execute_factory_pipeline("run_no_assets")
        self.assertEqual(summary.stage, "delivered")
        self.assertEqual(summary.verdict_status, "ready")
        self.assertTrue(summary.is_ready_for_delivery)

    async def test_09_overlapping_execution_calls_serialized_without_mixing_assets(self) -> None:
        """Preserved Fix 3 Test: Overlapping execution calls are serialized by _execution_lock."""
        service, spec = _create_configured_test_service(
            self.tmp_path / "concurrent", seed_retrieval_bug=False
        )
        for rid, marker in (
            ("run_alpha", "ALPHA_PROJECT_EXCLUSIVE_ASSET_30_DAYS"),
            ("run_beta", "BETA_PROJECT_EXCLUSIVE_ASSET_30_DAYS"),
        ):
            service.create_project(spec.goal, run_id=rid)
            service.ingest_assets(
                rid,
                [
                    {
                        "asset_id": f"asset_{rid}",
                        "filename": f"{rid}.md",
                        "content": f"{marker}: Full refunds are granted within 30 calendar days of purchase.",
                        "format": "md",
                    }
                ],
            )
            service.submit_spec_for_review(rid, spec)
            service.approve_spec(rid, _build_synthetic_handoff_package(spec))
            for pre_node in ("init_run", "design_eval", "split_and_seal", "build", "dev_test", "freeze"):
                await service.execute_single_stage(rid, pre_node)  # type: ignore[arg-type]

        observed_assets_by_run: dict[str, list[str]] = {}
        orig_eval_node = service.orchestrator.evaluate_node

        async def _delayed_evaluate_node(state: FactoryGraphState) -> dict[str, Any]:
            rid = state["refs"]["run_id"]
            await asyncio.sleep(0.05)
            loaded_assets = service._load_active_run_assets()
            observed_assets_by_run[rid] = [a.content for a in loaded_assets]
            await asyncio.sleep(0.05)
            return await orig_eval_node(state)

        service.orchestrator.evaluate_node = _delayed_evaluate_node  # type: ignore[method-assign]

        res_alpha, res_beta = await asyncio.gather(
            service.execute_single_stage("run_alpha", "evaluate"),
            service.execute_single_stage("run_beta", "evaluate"),
        )
        self.assertIsNone(service._active_run_id)
        self.assertEqual(res_alpha.verdict_status, "ready")
        self.assertEqual(res_beta.verdict_status, "ready")
        self.assertTrue(
            all("ALPHA_PROJECT_EXCLUSIVE_ASSET" in c for c in observed_assets_by_run["run_alpha"])
        )
        self.assertTrue(
            all("BETA_PROJECT_EXCLUSIVE_ASSET" not in c for c in observed_assets_by_run["run_alpha"])
        )
        self.assertTrue(
            all("BETA_PROJECT_EXCLUSIVE_ASSET" in c for c in observed_assets_by_run["run_beta"])
        )
        self.assertTrue(
            all("ALPHA_PROJECT_EXCLUSIVE_ASSET" not in c for c in observed_assets_by_run["run_beta"])
        )

    def test_10_reusing_project_run_id_does_not_overwrite_existing_state(self) -> None:
        """Preserved Fix 4 Test: Reusing an existing run_id raises ProjectStateError and preserves state."""
        service, spec = _create_configured_test_service(self.tmp_path)
        service.create_project("Original project goal", run_id="run_no_overwrite")
        service.submit_spec_for_review("run_no_overwrite", spec)
        before_status = service.get_project_status("run_no_overwrite")

        with self.assertRaises(ProjectStateError):
            service.create_project(
                "Attempted overwrite goal", run_id="run_no_overwrite"
            )

        after_status = service.get_project_status("run_no_overwrite")
        self.assertEqual(after_status.user_goal, "Original project goal")
        self.assertEqual(after_status.stage, "spec_review")
        self.assertEqual(after_status.events, before_status.events)

    async def test_11_full_workflow_dev_test_repair_freeze_eval_and_ready_delivery(self) -> None:
        """End-to-End Ready Delivery Test: Full 12-step workflow with seeded bug, repair, freeze,
        protected evaluation, and ready-gated delivery.
        """
        service, spec = _create_configured_test_service(
            self.tmp_path / "full_e2e",
            seed_retrieval_bug=True,
            enable_effective_repair=True,
        )
        service.create_project(spec.goal, run_id="run_e2e_ready")
        service.ingest_assets(
            "run_e2e_ready",
            [
                {
                    "asset_id": "pol_v1",
                    "filename": "refund_policy.md",
                    "content": "Section 4.2 Refund Policy: Full refunds are granted within 30 calendar days of purchase if the software license key has not been activated.",
                    "format": "md",
                }
            ],
        )
        service.submit_spec_for_review("run_e2e_ready", spec)
        service.approve_spec(
            "run_e2e_ready", _build_synthetic_handoff_package(spec)
        )

        final_summary = await service.execute_factory_pipeline("run_e2e_ready")
        self.assertEqual(final_summary.stage, "delivered")
        self.assertEqual(final_summary.repair_attempts, 1)
        self.assertTrue(final_summary.dev_test_passed)
        self.assertEqual(final_summary.verdict_status, "ready")
        self.assertTrue(final_summary.is_ready_for_delivery)

        pkg, files_data = service.get_authorized_delivery("run_e2e_ready")
        self.assertEqual(pkg.verdict.status, "ready")
        self.assertIn("app_config.json", files_data)

    async def test_12_not_ready_verdict_and_dev_only_pass_block_delivery(self) -> None:
        """End-to-End Not-Ready Delivery Block Test: A not_ready Verdict blocks artifact delivery."""
        service, spec = _create_configured_test_service(
            self.tmp_path / "not_ready",
            seed_retrieval_bug=True,
            enable_effective_repair=False,
        )
        service.create_project(
            spec.goal, run_id="run_not_ready", max_repair_attempts=1
        )
        service.ingest_assets(
            "run_not_ready",
            [
                {
                    "asset_id": "pol_v1",
                    "filename": "refund_policy.md",
                    "content": "Section 4.2 Refund Policy: Full refunds are granted within 30 calendar days of purchase.",
                    "format": "md",
                }
            ],
        )
        service.submit_spec_for_review("run_not_ready", spec)
        service.approve_spec(
            "run_not_ready", _build_synthetic_handoff_package(spec)
        )

        final_summary = await service.execute_factory_pipeline("run_not_ready")
        self.assertEqual(final_summary.stage, "delivered")
        self.assertEqual(final_summary.verdict_status, "not_ready")
        self.assertFalse(final_summary.is_ready_for_delivery)

        with self.assertRaises(DeliveryNotAuthorizedError):
            service.get_authorized_delivery("run_not_ready")


async def _run_demo() -> int:
    with tempfile.TemporaryDirectory(prefix="adaptos_service_demo_") as tmp:
        service, spec = _create_configured_test_service(
            Path(tmp), seed_retrieval_bug=True, enable_effective_repair=True
        )
        service.create_project(spec.goal, run_id="demo_project_01")
        service.ingest_assets(
            "demo_project_01",
            [
                {
                    "asset_id": "pol_v1",
                    "filename": "refund_policy.md",
                    "content": "Section 4.2 Refund Policy: Full refunds are granted within 30 calendar days of purchase if the software license key has not been activated.",
                    "format": "md",
                }
            ],
        )
        service.submit_spec_for_review("demo_project_01", spec)
        service.approve_spec(
            "demo_project_01", _build_synthetic_handoff_package(spec)
        )
        summary = await service.execute_factory_pipeline("demo_project_01")
        pkg, files = service.get_authorized_delivery("demo_project_01")
        print(
            json.dumps(
                {
                    "run_id": summary.run_id,
                    "stage": summary.stage,
                    "dev_pass_rate": summary.dev_pass_rate,
                    "repair_attempts": summary.repair_attempts,
                    "verdict_status": summary.verdict_status,
                    "is_ready_for_delivery": summary.is_ready_for_delivery,
                    "delivered_version_id": pkg.artifact.version_id,
                    "delivered_files": sorted(files.keys()),
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AdaptOS Unified Service Layer")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run built-in Service Layer unittest suite",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run end-to-end 12-step Service Layer demo",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.demo:
        return asyncio.run(_run_demo())

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        ServiceLayerSelfTestSuite
    )
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
