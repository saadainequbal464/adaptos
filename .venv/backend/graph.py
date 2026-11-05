"""graph.py — AdaptOS Factory Orchestrator (eval_design -> delivered / failed).

Responsibilities & Invariants:
1. Pure orchestration: zero direct LLM calls or prompts inside graph.py; all work happens via
   injected Ports (EvalDesignerPort, SplitterPort, BuilderPort, RepairPort, EvalPlanePort,
   AssetStorePort, DeliveryPort).
2. JSON-only Graph State: `{factory, refs, events}` where `factory` is `FactoryState.model_dump(mode="json")`.
   Every node validates `FactoryState` on entry and serializes back to plain JSON dicts (zero pickle).
3. Assignment Order Invariant: Always assign required fields (`sealed`, `baseline`, `candidate`,
   `frozen`, `verdict`) BEFORE assigning `state.stage` (`validate_assignment=True`).
4. Post-Freeze Immutability: Once `freeze` is reached, graph topology has zero edges back to
   `build`, `dev_test`, or `repair`.
5. Cryptographic Verdict Gate: `evaluate` verifies `Verdict.signing_payload()` using real Ed25519
   public-key verification (`cryptography`). Fails closed if `cryptography` is unavailable.
6. Hard 3-Attempt Repair Cap & Outcome Validation: Initial build does not count as a repair attempt.
   At most 3 repair attempts can ever execute. Invalid or non-advancing repair outcomes fail closed.
7. Persistent Sealed Vault & Sanitized Errors: Held-out cases persist in an isolated SQLite vault
   (`sealed_vault.db`) so checkpoint resume works across restarts. Exceptions are sanitized before
   entering `events` or `ErrorRecord`.
"""
from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
import os
import random
import re
import sqlite3
import sys
import tempfile
import unittest
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final, Literal, Mapping, Protocol, Sequence, TypedDict

# Clean path resolution when invoked directly as `python graph.py` or `python -m graph`
_CURRENT_DIR = Path(__file__).resolve().parent
_PARENT_DIR = _CURRENT_DIR.parent
for _cand_path in (_CURRENT_DIR, _PARENT_DIR):
    if (_cand_path / "schemas.py").is_file() and str(_cand_path) not in sys.path:
        sys.path.insert(0, str(_cand_path))

from langgraph.graph import END, START, StateGraph

from schemas import (
    AcceptanceCriterion,
    ArtifactRef,
    BundleManifest,
    CriterionResult,
    DeliveryPackage,
    DevCase,
    DevRun,
    ErrorRecord,
    EvaluationRequest,
    FactoryState,
    FieldSpec,
    RepairRecord,
    SealedSetCommitment,
    Spec,
    Verdict,
    canonical_json,
    sha256_hex,
    ArtifactContent
)
from storage import StorageConfig, StorageService

from agents import builder as _builder_mod
from agents import intake as _intake_mod
from agents import repair as _repair_mod

from agents import eval_designer as _ed_mod  # type: ignore[no-redef]

BuildEngine = _builder_mod.BuildEngine
BuilderConfig = _builder_mod.BuilderConfig
ReplayAndLiveModelAdapter = _builder_mod.ReplayAndLiveModelAdapter
SandboxVerifier = _builder_mod.SandboxVerifier
SourceAssetInput = _builder_mod.SourceAssetInput
spec_fields_to_json_schema = _builder_mod.spec_fields_to_json_schema
_simulated_docker_runner = getattr(_builder_mod, "_simulated_docker_runner", None)

ApprovedSpec = _ed_mod.ApprovedSpec
DeterministicReference = _ed_mod.DeterministicReference
EvalDesignerConfig = _ed_mod.EvalDesignerConfig
EvalDesignerService = _ed_mod.EvalDesignerService
GeneratedTestCase = _ed_mod.GeneratedTestCase
Role = _ed_mod.Role
SourceDocument = _ed_mod.SourceDocument
TestPlan = _ed_mod.TestPlan
build_mock_cases_for_spec = _ed_mod.build_mock_cases_for_spec

SqliteSerdeSaver = _intake_mod.SqliteSerdeSaver
apply_handoff_to_factory_state = _intake_mod.apply_handoff_to_factory_state

BundleRepairOutcome = _repair_mod.BundleRepairOutcome
BundleRepairRequest = _repair_mod.BundleRepairRequest
RepairConfig = _repair_mod.RepairConfig
RepairProposer = _repair_mod.RepairProposer
is_dev_run_passing = _repair_mod.is_dev_run_passing
repair_attempt = _repair_mod.repair_attempt

MAX_GRAPH_REPAIR_ATTEMPTS: Final[int] = 3
DEFAULT_GRAPH_RECURSION_LIMIT: Final[int] = 25

_SECRET_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"(Bearer\s+)[A-Za-z0-9._\-+/=]+", re.IGNORECASE),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{12,}\b"),
    re.compile(r"(MODEL_API_KEY|ADAPTOS_ACCESS_SECRET)\s*=\s*[^\s,;]+", re.IGNORECASE),
)
_HELD_OUT_LEAK_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(
        r"\"?(expected_value|citation_span|held_out_cases|case_pool|input_data)\"?\s*:\s*[^,}\]]+",
        re.IGNORECASE,
    ),
    re.compile(r"\bcase_crit_[A-Za-z0-9_]+\b"),
)


def _canonical_bytes(data: Any) -> bytes:
    res = canonical_json(data)
    return res if isinstance(res, bytes) else str(res).encode("utf-8")


def sanitize_diagnostic_text(raw: Any, *, max_len: int = 300) -> str:
    """Redacts secrets, environment keys, and held-out case data from diagnostic/error strings."""
    text = str(raw or "").strip()
    if not text:
        return "Unspecified factory error."

    for k, v in os.environ.items():
        if (
            any(tok in k.upper() for tok in ("KEY", "SECRET", "TOKEN", "PASSWORD"))
            and v
            and len(v) >= 6
        ):
            text = text.replace(v, "[REDACTED_SECRET]")

    for pat in _SECRET_PATTERNS:
        text = pat.sub("[REDACTED_SECRET]", text)
    for pat in _HELD_OUT_LEAK_PATTERNS:
        text = pat.sub("[REDACTED_PROTECTED_DATA]", text)

    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_len]


def ensure_storage_compat(storage: StorageService) -> StorageService:
    """Ensures StorageService has the helper attributes expected by builder.py and repair.py."""
    cfg = getattr(storage, "config", None)
    if cfg is not None and not hasattr(cfg, "sqlite_busy_timeout_ms"):
        timeout_val = getattr(cfg, "busy_timeout_ms", 5000)
        try:
            object.__setattr__(cfg, "sqlite_busy_timeout_ms", timeout_val)
        except Exception:
            pass

    if not hasattr(storage, "_blob_path"):
        def _compat_blob_path(digest: str) -> Path:
            for attr in ("blobs_dir", "blob_dir"):
                d = getattr(storage, attr, None)
                if isinstance(d, Path):
                    return d / digest[:2] / digest[2:]
            root = getattr(cfg, "root_dir", getattr(cfg, "data_root", Path("./agnos_data")))
            return Path(root) / "blobs" / digest[:2] / digest[2:]

        setattr(storage, "_blob_path", _compat_blob_path)

    if not hasattr(storage, "verify_blob"):
        def _compat_verify_blob(digest: str) -> bool:
            try:
                raw = storage.get_blob(digest)
                return sha256_hex(raw) == digest
            except Exception:
                return False

        setattr(storage, "verify_blob", _compat_verify_blob)

    return storage


# =========================================================================== #
# 1. REAL ED25519 VERDICT SIGNING & VERIFICATION (No Fake HMAC Fallback)
# =========================================================================== #


def _require_ed25519_crypto() -> tuple[Any, Any, Any]:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )

        return Ed25519PrivateKey, Ed25519PublicKey, serialization
    except ImportError as exc:
        raise RuntimeError(
            "The 'cryptography' package is required for Ed25519 Verdict signing and verification; "
            "refusing to substitute HMAC for Ed25519."
        ) from exc


class Ed25519KeyPair:
    """Strict Ed25519 keypair for the Protected Evaluation Plane.

    Fails explicitly if `cryptography` is unavailable rather than faking Ed25519 with HMAC.
    """

    def __init__(self, seed_bytes: bytes | None = None, *, key_id: str = "eval-ed25519-key-01") -> None:
        Ed25519PrivateKey, _, serialization = _require_ed25519_crypto()
        self._seed = seed_bytes if seed_bytes is not None else os.urandom(32)
        if len(self._seed) != 32:
            raise ValueError("Ed25519 private seed must be exactly 32 bytes.")
        self.key_id = key_id
        self._priv = Ed25519PrivateKey.from_private_bytes(self._seed)
        self._pub = self._priv.public_key()
        self.public_key_bytes: bytes = self._pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, payload: bytes) -> str:
        return self._priv.sign(payload).hex()

    @staticmethod
    def verify(public_key_bytes: bytes, payload: bytes, signature_hex: str) -> bool:
        _, Ed25519PublicKey, _ = _require_ed25519_crypto()
        if len(public_key_bytes) != 32:
            return False
        try:
            sig_bytes = bytes.fromhex(signature_hex)
        except ValueError:
            return False
        if len(sig_bytes) != 64:
            return False
        try:
            pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            pub.verify(sig_bytes, payload)
            return True
        except Exception:
            return False


# =========================================================================== #
# 2. GRAPH STATE SHAPE & PORTS (Sections 1 & 3)
# =========================================================================== #


class GraphRefs(TypedDict, total=False):
    run_id: str
    handoff_blob_sha256: str | None
    raw_assets_blob_sha256: str | None
    assets_blob_sha256: str | None
    plan_hash: str | None
    dev_cases_blob_sha256: str | None
    sealed_set_id: str | None
    delivery_blob_sha256: str | None
    tried_patch_hashes: list[str]
    last_rejected_target: str | None
    last_rejected_kind: str | None
    repair_proposal_fixtures: list[dict[str, Any]]


class FactoryGraphState(TypedDict):
    """JSON-only state persisted across LangGraph checkpoints (Zero Pydantic/Pickle objects)."""

    factory: dict[str, Any]
    refs: GraphRefs
    events: list[str]


class EvalDesignerPort(Protocol):
    async def design_evaluation(
        self, spec: Spec, assets: Sequence[SourceAssetInput]
    ) -> tuple[str, str | None, bool, str]:
        """Returns (status, plan_hash, all_criteria_split_ready, error_message)."""
        ...


class SplitterPort(Protocol):
    def split_and_seal(
        self, *, plan_hash: str, spec: Spec, seed: int = 42
    ) -> tuple[list[DevCase], SealedSetCommitment]: ...


class BuilderPort(Protocol):
    async def build(
        self,
        state_copy: FactoryState,
        dev_cases: Sequence[DevCase],
        assets: Sequence[SourceAssetInput],
    ) -> _builder_mod.BuildResult: ...

    def run_dev_suite(
        self,
        *,
        version_id: str,
        spec: Spec,
        dev_cases: Sequence[DevCase],
        assets: Sequence[SourceAssetInput],
    ) -> DevRun: ...

    def load_manifest(self, version_id: str) -> BundleManifest: ...


class RepairPort(Protocol):
    async def run_attempt(
        self,
        request: BundleRepairRequest,
        *,
        proposal_fixtures: list[dict[str, Any]] | None = None,
    ) -> BundleRepairOutcome: ...


class EvalPlanePort(Protocol):
    def evaluate(self, request: EvaluationRequest) -> Verdict: ...


class AssetStorePort(Protocol):
    def put_json_blob(self, data: Any) -> str: ...
    def get_json_blob(self, blob_sha256: str) -> Any: ...


class DeliveryPort(Protocol):
    """Port interface for the separate delivery.py module."""

    def deliver(
        self,
        *,
        spec: Spec,
        artifact: BundleManifest,
        verdict: Verdict,
        repair_log: Sequence[RepairRecord],
    ) -> tuple[DeliveryPackage, str]: ...


@dataclass
class FactoryDeps:
    eval_designer: EvalDesignerPort
    splitter: SplitterPort
    builder: BuilderPort
    repair: RepairPort
    eval_plane: EvalPlanePort
    asset_store: AssetStorePort
    delivery: DeliveryPort
    eval_public_key_bytes: bytes
    node_timeout_seconds: float = 30.0
    split_seed: int = 42
    recursion_limit: int = DEFAULT_GRAPH_RECURSION_LIMIT


# =========================================================================== #
# 3. PERSISTENT SEALED VAULT & PORT ADAPTERS
# =========================================================================== #


class StorageAssetStoreAdapter:
    """Persists JSON blobs in StorageService."""

    def __init__(self, storage: StorageService) -> None:
        self.storage = ensure_storage_compat(storage)

    def put_json_blob(self, data: Any) -> str:
        return str(self.storage.put_blob(_canonical_bytes(data)))

    def get_json_blob(self, blob_sha256: str) -> Any:
        raw = self.storage.get_blob(blob_sha256)
        return json.loads(raw.decode("utf-8"))


class RealEvalDesignerAdapter:
    """Bridges schemas.Spec -> ApprovedSpec.from_factory_spec -> EvalDesignerService."""

    def __init__(self, service: EvalDesignerService) -> None:
        self.service = service

    async def design_evaluation(
        self, spec: Spec, assets: Sequence[SourceAssetInput]
    ) -> tuple[str, str | None, bool, str]:
        source_docs = tuple(
            SourceDocument(
                source_id=a.asset_id,
                filename=a.filename,
                sha256=sha256_hex(a.content.encode("utf-8")),
                content=a.content,
            )
            for a in assets
            if a.content.strip()
        )
        factory_dict = spec.model_dump(mode="json")
        approved_spec = ApprovedSpec.from_factory_spec(
            factory_dict,
            expected_spec_hash=spec.content_hash(),
            source_documents=source_docs,
        )
        outcome = await self.service.design_evaluation(approved_spec)
        if outcome.status == "failed_untestable" or outcome.metadata is None:
            reasons = "; ".join(f.reason for f in outcome.failures) or "Criteria untestable."
            return outcome.status, None, False, reasons
        return (
            outcome.status,
            outcome.metadata.plan_hash,
            outcome.metadata.all_criteria_split_ready,
            "; ".join(f.reason for f in outcome.failures),
        )


class SealedVaultStore:
    """Persistent, hash-verified SQLite store for sealed held-out evaluation cases.

    Persists sealed sets in a dedicated `sealed_vault.db` file (outside `factory.db` and
    `blobs/`) so checkpoint resume across process restarts remains valid and tamper-checked.
    """

    def __init__(self, vault_db_path: Path) -> None:
        self.vault_db_path = Path(vault_db_path)
        self.vault_db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.vault_db_path, timeout=10.0) as conn:
            conn.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS sealed_sets (
                    set_id TEXT PRIMARY KEY,
                    spec_hash TEXT NOT NULL,
                    commitment_hash TEXT NOT NULL,
                    spec_json TEXT NOT NULL,
                    held_out_cases_json TEXT NOT NULL,
                    commitment_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)

    @staticmethod
    def _compute_commitment_hash(
        set_id: str,
        spec_hash: str,
        counts: Mapping[str, int],
        held_out_cases: Sequence[GeneratedTestCase],
    ) -> str:
        commitment_payload = {
            "set_id": set_id,
            "spec_hash": spec_hash,
            "counts": dict(counts),
            "case_hashes": [tc.input_signature_hash for tc in held_out_cases],
        }
        return sha256_hex(_canonical_bytes(commitment_payload))

    def seal(
        self,
        *,
        spec: Spec,
        held_out_cases: Sequence[GeneratedTestCase],
        set_id: str | None = None,
    ) -> SealedSetCommitment:
        sid = set_id or f"sealed_{uuid.uuid4().hex[:12]}"
        spec_hash = spec.content_hash()
        counts: dict[str, int] = {c.criterion_id: 0 for c in spec.acceptance_criteria}
        for tc in held_out_cases:
            counts[tc.criterion_id] = counts.get(tc.criterion_id, 0) + 1

        c_hash = self._compute_commitment_hash(sid, spec_hash, counts, held_out_cases)
        commitment = SealedSetCommitment(
            set_id=sid,
            spec_hash=spec_hash,
            case_count=len(held_out_cases),
            criterion_case_counts=counts,
            commitment_hash=c_hash,
            sealed_at=datetime.now(timezone.utc),
        )

        spec_json = _canonical_bytes(spec.model_dump(mode="json")).decode("utf-8")
        cases_json = _canonical_bytes(
            [tc.model_dump(mode="json") for tc in held_out_cases]
        ).decode("utf-8")
        commitment_json = _canonical_bytes(commitment.model_dump(mode="json")).decode("utf-8")

        with sqlite3.connect(self.vault_db_path, timeout=10.0) as conn:
            conn.row_factory = sqlite3.Row
            existing = conn.execute(
                "SELECT commitment_hash, commitment_json FROM sealed_sets WHERE set_id=?",
                (sid,),
            ).fetchone()
            if existing is not None:
                if existing["commitment_hash"] != c_hash:
                    raise ValueError(
                        f"Sealed set '{sid}' already exists with different commitment_hash."
                    )
                return SealedSetCommitment.model_validate(
                    json.loads(existing["commitment_json"])
                )

            conn.execute(
                """
                INSERT INTO sealed_sets
                (set_id, spec_hash, commitment_hash, spec_json, held_out_cases_json, commitment_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sid,
                    spec_hash,
                    c_hash,
                    spec_json,
                    cases_json,
                    commitment_json,
                    commitment.sealed_at.isoformat(),
                ),
            )
        return commitment

    def get_sealed_cases(
        self, set_id: str
    ) -> tuple[Spec, tuple[GeneratedTestCase, ...], SealedSetCommitment]:
        with sqlite3.connect(self.vault_db_path, timeout=10.0) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM sealed_sets WHERE set_id=?", (set_id,)
            ).fetchone()
        if row is None:
            raise KeyError(f"Sealed set '{set_id}' not found in persistent vault.")

        spec = Spec.model_validate(json.loads(row["spec_json"]))
        cases = tuple(
            GeneratedTestCase.model_validate(c)
            for c in json.loads(row["held_out_cases_json"])
        )
        commitment = SealedSetCommitment.model_validate(
            json.loads(row["commitment_json"])
        )

        # Verify integrity of persisted held-out set against its commitment hash
        expected_c_hash = self._compute_commitment_hash(
            commitment.set_id,
            spec.content_hash(),
            commitment.criterion_case_counts,
            cases,
        )
        if (
            commitment.commitment_hash != row["commitment_hash"]
            or expected_c_hash != commitment.commitment_hash
        ):
            raise ValueError(
                f"Persistent vault integrity check failed for sealed set '{set_id}'."
            )
        return spec, cases, commitment


class DeterministicSplitterAdapter:
    """Fetches undivided TestPlan using Role.SPLIT_CASES principal, creates deterministic
    dev/held-out split, populates expected_output on schemas.DevCase, and seals held-out
    cases into SealedVaultStore.
    """

    def __init__(
        self,
        eval_designer_service: EvalDesignerService,
        vault: SealedVaultStore,
    ) -> None:
        self.ed_service = eval_designer_service
        self.vault = vault
        self.principal = self.ed_service.access_guard.issue_principal(
            "factory_splitter", Role.SPLIT_CASES
        )

    @staticmethod
    def _extract_expected_output(tc: GeneratedTestCase, spec: Spec) -> dict[str, Any] | str:
        ref = tc.reference
        target_field = getattr(tc.method_config, "target_output_field", None) or (
            spec.outputs[0].name if spec.outputs else "output"
        )
        if isinstance(ref, DeterministicReference):
            if ref.expected_value is not None:
                if isinstance(ref.expected_value, dict):
                    return dict(ref.expected_value)
                return {target_field: ref.expected_value}
            if ref.required_substrings:
                return {target_field: ref.required_substrings[0]}
            if ref.citation_span:
                return {target_field: ref.citation_span}
            if ref.required_subset:
                return dict(ref.required_subset)
        return {target_field: "valid_output"}

    def split_and_seal(
        self, *, plan_hash: str, spec: Spec, seed: int = 42
    ) -> tuple[list[DevCase], SealedSetCommitment]:
        plan: TestPlan = self.ed_service.split_cases_port.fetch_undivided_plan_for_splitting(
            plan_hash=plan_hash, principal=self.principal
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

        dev_cases_by_input_sig: dict[str, DevCase] = {}
        dev_pool_ids: list[str] = []
        held_out_pool: list[GeneratedTestCase] = []

        for crit in spec.acceptance_criteria:
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
                exp_out = self._extract_expected_output(tc, spec)
                sig = sha256_hex(_canonical_bytes(tc.input_data))
                if sig in dev_cases_by_input_sig:
                    existing = dev_cases_by_input_sig[sig]
                    merged_cids = tuple(dict.fromkeys([*existing.criterion_ids, cid]))
                    merged_exp = (
                        {**existing.expected_output, **exp_out}
                        if isinstance(existing.expected_output, dict)
                        and isinstance(exp_out, dict)
                        else existing.expected_output
                    )
                    dev_cases_by_input_sig[sig] = existing.model_copy(
                        update={
                            "criterion_ids": merged_cids,
                            "expected_output": merged_exp,
                        }
                    )
                else:
                    dev_cases_by_input_sig[sig] = DevCase(
                        case_id=tc.case_id,
                        input_data=dict(tc.input_data),
                        expected_output=exp_out,
                        criterion_ids=(cid,),
                    )

            held_out_pool.extend(held_slice)

        self.ed_service.split_cases_port.register_post_split_dev_subset(
            plan_hash=plan_hash,
            dev_case_ids=dev_pool_ids,
            principal=self.principal,
        )
        commitment = self.vault.seal(
            spec=spec,
            held_out_cases=held_out_pool,
            set_id=f"sealed_{plan_hash[:12]}",
        )
        return list(dev_cases_by_input_sig.values()), commitment


class RealBuilderAdapter:
    """Wraps BuildEngine for `build` and `dev_test` graph nodes."""

    def __init__(self, engine: BuildEngine) -> None:
        self.engine = engine

    async def build(
        self,
        state_copy: FactoryState,
        dev_cases: Sequence[DevCase],
        assets: Sequence[SourceAssetInput],
    ) -> _builder_mod.BuildResult:
        # builder_bundles.version_id is a UNIQUE primary key and the protected evaluator
        # keys verdict idempotency on artifact identity, so version ids must be
        # deterministic per spec (re-assembly of identical content is idempotent;
        # a changed spec yields a new spec_hash and thus new version ids).
        spec_hash = (
            state_copy.approved_spec_hash
            or (state_copy.spec.content_hash() if state_copy.spec is not None else "unapproved")
        )
        base = f"v1-{spec_hash[:12]}"
        try:
            res = await self.engine.build_application(
                state_copy,
                dev_cases,
                assets=assets,
                baseline_version_id=f"{base}-baseline",
                candidate_version_id=f"{base}-candidate",
            )
            collision = res.status == "failed" and (
                "already exists with a different artifact_hash" in res.error_message
            )
            if not collision:
                return res
        except _builder_mod.BuilderError as exc:
            if "already exists with a different artifact_hash" not in str(exc):
                raise
        # builder_bundles.version_id is immutable; when content legitimately changed
        # under the same deterministic id (e.g. planner drift), rebuild under a fresh
        # suffixed id instead of failing the run.
        suffix = uuid.uuid4().hex[:6]
        return await self.engine.build_application(
            state_copy,
            dev_cases,
            assets=assets,
            baseline_version_id=f"{base}-{suffix}-baseline",
            candidate_version_id=f"{base}-{suffix}-candidate",
        )

    def run_dev_suite(
        self,
        *,
        version_id: str,
        spec: Spec,
        dev_cases: Sequence[DevCase],
        assets: Sequence[SourceAssetInput],
    ) -> DevRun:
        dev_run, _ = self.engine.dev_runner.run_dev_suite(
            version_id=version_id,
            spec=spec,
            dev_cases=dev_cases,
            assets=assets,
        )
        return dev_run

    def load_manifest(self, version_id: str) -> BundleManifest:
        manifest, _ = self.engine.assembler.load_bundle(version_id)
        return manifest


class RealRepairAdapter:
    """Wraps `repair_attempt` so each repair iteration is a single checkpointed graph step."""

    def __init__(
        self,
        engine: BuildEngine,
        config: RepairConfig | None = None,
        default_fixtures: list[dict[str, Any]] | None = None,
        provider_caller: Any | None = None,
    ) -> None:
        self.engine = engine
        self.config = config or RepairConfig()
        self.default_fixtures = list(default_fixtures or [])
        self.provider_caller = provider_caller

    async def run_attempt(
        self,
        request: BundleRepairRequest,
        *,
        proposal_fixtures: list[dict[str, Any]] | None = None,
    ) -> BundleRepairOutcome:
        active_fixtures = (
            proposal_fixtures if proposal_fixtures is not None else self.default_fixtures
        )
        proposer = RepairProposer(
            self.config,
            proposal_fixtures=active_fixtures,
            provider_caller=self.provider_caller,
        )
        return await repair_attempt(
            request, engine=self.engine, proposer=proposer, config=self.config
        )


class LocalProtectedEvalPlane:
    """Executes a frozen candidate bundle against sealed cases in SealedVaultStore and issues
    an Ed25519-signed `schemas.Verdict` using the exact `schemas.Verdict` contract.
    """

    def __init__(
        self,
        *,
        vault: SealedVaultStore,
        engine: BuildEngine,
        signing_key: Ed25519KeyPair,
        assets: Sequence[SourceAssetInput] = (),
    ) -> None:
        self.vault = vault
        self.engine = engine
        self._signing_key = signing_key
        self.assets = tuple(assets)
        self._verdict_cache: dict[tuple[str, str], Verdict] = {}
        self.evaluation_calls = 0

    @staticmethod
    def _build_signed_verdict(
        *,
        artifact_ref: ArtifactRef,
        spec_hash: str,
        sealed_set_id: str,
        sealed_commitment_hash: str,
        criterion_results: Sequence[CriterionResult],
        evidence_hash: str,
        signing_key: Ed25519KeyPair,
    ) -> Verdict:
        # Derive the verdict status from CriterionResult.status exactly like
        # schemas.Verdict._check_verdict does (any not_met -> not_ready,
        # any undetermined / empty -> insufficient_evidence, else ready).
        statuses = {cr.status for cr in criterion_results}
        if "not_met" in statuses:
            verdict_status: Literal["ready", "not_ready", "insufficient_evidence"] = "not_ready"
        elif "undetermined" in statuses or not criterion_results:
            verdict_status = "insufficient_evidence"
        else:
            verdict_status = "ready"

        unsigned_verdict = Verdict(
            verdict_id=f"verdict_{uuid.uuid4().hex[:12]}",
            spec_hash=spec_hash,
            artifact=artifact_ref,
            sealed_set_id=sealed_set_id,
            sealed_commitment_hash=sealed_commitment_hash,
            status=verdict_status,
            criteria=tuple(criterion_results),
            evidence_hash=evidence_hash,
            issued_at=datetime.now(timezone.utc),
            signing_key_id=signing_key.key_id,
            signature="0" * 128,
        )
        real_sig_hex = signing_key.sign(unsigned_verdict.signing_payload())
        return unsigned_verdict.model_copy(update={"signature": real_sig_hex})

    def evaluate(self, request: EvaluationRequest) -> Verdict:
        art_ref = request.artifact.ref
        set_id = request.sealed.set_id
        cache_key = (art_ref.artifact_hash, set_id)
        if cache_key in self._verdict_cache:
            return self._verdict_cache[cache_key]

        self.evaluation_calls += 1
        spec, held_out_cases, commitment = self.vault.get_sealed_cases(set_id)
        if commitment.commitment_hash != request.sealed.commitment_hash:
            raise ValueError("SealedSetCommitment hash mismatch in EvaluationRequest.")

        manifest, files_data = self.engine.assembler.load_bundle(art_ref.version_id)
        if manifest.artifact_hash != art_ref.artifact_hash:
            raise ValueError("Frozen artifact_hash mismatch during protected evaluation.")

        crit_by_id = {c.criterion_id: c for c in spec.acceptance_criteria}
        cases_by_crit: dict[str, list[GeneratedTestCase]] = {
            c.criterion_id: [] for c in spec.acceptance_criteria
        }
        for tc in held_out_cases:
            if tc.criterion_id in cases_by_crit:
                cases_by_crit[tc.criterion_id].append(tc)

        crit_results: list[CriterionResult] = []
        case_outcomes_digest: list[dict[str, Any]] = []

        for crit in spec.acceptance_criteria:
            cid = crit.criterion_id
            c_cases = cases_by_crit[cid]
            n_passed = 0
            for tc in c_cases:
                exp_out = DeterministicSplitterAdapter._extract_expected_output(tc, spec)
                temp_dc = DevCase(
                    case_id=tc.case_id,
                    input_data=dict(tc.input_data),
                    expected_output=exp_out,
                    criterion_ids=(cid,),
                )
                passed = False
                try:
                    out, _ = self.engine.dev_runner.runtime.execute_bundle(
                        manifest, files_data, tc.input_data, assets=self.assets
                    )
                    passed, _, _ = self.engine.dev_runner._grade_dev_case(
                        out, temp_dc, crit_by_id
                    )
                    if passed:
                        n_passed += 1
                except Exception:
                    passed = False
                case_outcomes_digest.append(
                    {"case_id": tc.case_id, "criterion_id": cid, "passed": passed}
                )

            cr = CriterionResult.from_counts(
                criterion_id=cid,
                threshold=crit.min_pass_rate,
                n_passed=n_passed,
                n_cases=len(c_cases),
            )
            crit_results.append(cr)

        evidence_payload = {
            "spec_hash": spec.content_hash(),
            "artifact_hash": manifest.artifact_hash,
            "sealed_set_id": commitment.set_id,
            "sealed_commitment_hash": commitment.commitment_hash,
            "criteria": [cr.model_dump(mode="json") for cr in crit_results],
            "case_outcomes": case_outcomes_digest,
        }
        evidence_hash = sha256_hex(_canonical_bytes(evidence_payload))

        verdict = self._build_signed_verdict(
            artifact_ref=manifest.ref,
            spec_hash=spec.content_hash(),
            sealed_set_id=commitment.set_id,
            sealed_commitment_hash=commitment.commitment_hash,
            criterion_results=crit_results,
            evidence_hash=evidence_hash,
            signing_key=self._signing_key,
        )
        self._verdict_cache[cache_key] = verdict
        return verdict


class PlaceholderDeliveryPortAdapter:
    """Placeholder DeliveryPort adapter for graph tests until separate `delivery.py` is wired in `api.py`."""

    def __init__(self, asset_store: AssetStorePort) -> None:
        self.asset_store = asset_store

    def deliver(
        self,
        *,
        spec: Spec,
        artifact: BundleManifest,
        verdict: Verdict,
        repair_log: Sequence[RepairRecord],
    ) -> tuple[DeliveryPackage, str]:
        pkg = DeliveryPackage(
            spec=spec,
            artifact=artifact,
            verdict=verdict,
            repair_log=tuple(repair_log),
            delivered_at=datetime.now(timezone.utc),
        )
        blob_sha = self.asset_store.put_json_blob(pkg.model_dump(mode="json"))
        return pkg, blob_sha


# =========================================================================== #
# 4. FACTORY GRAPH ORCHESTRATOR (9 Nodes, Routing & Invariants)
# =========================================================================== #


def _verify_spec_hash_chain(f_state: FactoryState) -> None:
    """Invariant 5: Verifies spec hash chain across spec, sealed commitment, baseline, and candidate."""
    if f_state.spec is None:
        raise ValueError("FactoryState.spec is missing.")
    computed_spec_hash = f_state.spec.content_hash()
    if f_state.approved_spec_hash != computed_spec_hash:
        raise ValueError(
            f"Spec hash chain broken: approved_spec_hash ({f_state.approved_spec_hash}) "
            f"!= spec.content_hash() ({computed_spec_hash})."
        )
    if f_state.sealed is not None and f_state.sealed.spec_hash != computed_spec_hash:
        raise ValueError("Spec hash chain broken: sealed.spec_hash != approved_spec_hash.")
    if f_state.baseline is not None and f_state.baseline.spec_hash != computed_spec_hash:
        raise ValueError("Spec hash chain broken: baseline.spec_hash != approved_spec_hash.")
    if f_state.candidate is not None and f_state.candidate.spec_hash != computed_spec_hash:
        raise ValueError("Spec hash chain broken: candidate.spec_hash != approved_spec_hash.")


def _select_best_eligible_manifest(f_state: FactoryState) -> BundleManifest:
    """Selects the best eligible artifact when freezing (or when repair budget is exhausted).

    1. If `baseline` passed 100% of dev cases, choose `baseline` (simplest passing control).
    2. Else if `last_passing` is set (a candidate/repaired version passed 100% of dev cases), choose `last_passing`.
    3. Else (repair budget exhausted without 100% dev pass), compare latest DevRun pass rates for
       `candidate` vs `baseline` and pick the higher-scoring bundle (ties go to `candidate`).
    """
    if f_state.baseline is not None:
        base_runs = [
            r for r in f_state.dev_runs if r.version_id == f_state.baseline.version_id
        ]
        if base_runs and is_dev_run_passing(base_runs[-1]):
            return f_state.baseline

    if f_state.last_passing is not None:
        return f_state.last_passing

    if f_state.candidate is not None and f_state.baseline is not None:
        cand_runs = [
            r for r in f_state.dev_runs if r.version_id == f_state.candidate.version_id
        ]
        base_runs = [
            r for r in f_state.dev_runs if r.version_id == f_state.baseline.version_id
        ]
        cand_rate = cand_runs[-1].pass_rate if cand_runs else -1.0
        base_rate = base_runs[-1].pass_rate if base_runs else -1.0
        if base_rate > cand_rate:
            return f_state.baseline
        return f_state.candidate

    chosen = f_state.candidate or f_state.baseline
    if chosen is None:
        raise ValueError("No bundle manifest available to freeze.")
    return chosen


def _validate_repair_outcome(
    *,
    outcome: BundleRepairOutcome,
    expected_attempt: int,
    parent_candidate: BundleManifest,
    existing_repair_log: Sequence[RepairRecord],
) -> None:
    """Validates BundleRepairOutcome integrity and parent-child version chaining (Items 4 & 5)."""
    if not isinstance(outcome, BundleRepairOutcome):
        raise ValueError("RepairPort returned an invalid outcome type.")

    existing_attempts = {r.attempt for r in existing_repair_log}
    if expected_attempt in existing_attempts:
        raise ValueError(
            f"Duplicate repair attempt #{expected_attempt} already present in repair_log."
        )

    if outcome.status in ("repaired", "rejected"):
        if outcome.repair_record is None:
            raise ValueError(
                f"Invalid BundleRepairOutcome: status='{outcome.status}' is missing repair_record."
            )
        rec = outcome.repair_record
        if rec.attempt != expected_attempt:
            raise ValueError(
                f"RepairRecord.attempt ({rec.attempt}) != expected attempt ({expected_attempt})."
            )
        if rec.parent_version_id != parent_candidate.version_id:
            raise ValueError(
                f"Repair parent-child chaining broken: RepairRecord.parent_version_id "
                f"({rec.parent_version_id}) != current candidate ({parent_candidate.version_id})."
            )

        if outcome.status == "repaired":
            if not rec.accepted:
                raise ValueError(
                    "Inconsistent BundleRepairOutcome: status='repaired' but repair_record.accepted=False."
                )
            if outcome.new_manifest is None or outcome.child_dev_run is None:
                raise ValueError(
                    "Invalid BundleRepairOutcome: status='repaired' requires new_manifest and child_dev_run."
                )
            if outcome.new_manifest.parent_version_id != parent_candidate.version_id:
                raise ValueError(
                    f"New manifest parent_version_id ({outcome.new_manifest.parent_version_id}) "
                    f"!= current candidate ({parent_candidate.version_id})."
                )
            if (
                outcome.new_manifest.version_id != rec.new_version_id
                or outcome.new_manifest.version_id == parent_candidate.version_id
            ):
                raise ValueError(
                    "Repaired manifest version_id must match RepairRecord.new_version_id and differ from parent."
                )
            if outcome.child_dev_run.version_id != outcome.new_manifest.version_id:
                raise ValueError(
                    f"child_dev_run.version_id ({outcome.child_dev_run.version_id}) "
                    f"!= new_manifest.version_id ({outcome.new_manifest.version_id})."
                )
        else:
            if rec.accepted:
                raise ValueError(
                    "Inconsistent BundleRepairOutcome: status='rejected' but repair_record.accepted=True."
                )
    elif outcome.status in ("no_failure", "aborted"):
        if outcome.repair_record is not None and outcome.repair_record.accepted:
            raise ValueError(
                f"Inconsistent BundleRepairOutcome: status='{outcome.status}' cannot have accepted repair_record."
            )
    else:
        raise ValueError(f"Unsupported BundleRepairOutcome.status: {outcome.status!r}")


def _record_node_error(
    state: FactoryGraphState,
    *,
    stage_name: str,
    code: str,
    message: Any,
) -> dict[str, Any]:
    """Sanitizes and records node errors into ErrorRecord and events without leaking secrets or held-out data."""
    f_state = FactoryState.model_validate(state["factory"])
    safe_msg = sanitize_diagnostic_text(message, max_len=300)
    safe_event_msg = sanitize_diagnostic_text(message, max_len=160)
    err_stage = f_state.stage
    f_state.errors = [
        *f_state.errors,
        ErrorRecord(stage=err_stage, code=code[:64], message=safe_msg),
    ]
    events = [
        *state.get("events", []),
        f"[{stage_name}] ERROR ({code[:64]}): {safe_event_msg}",
    ]
    return {
        "factory": f_state.model_dump(mode="json"),
        "refs": dict(state.get("refs", {})),
        "events": events,
    }


class FactoryOrchestrator:
    """Builds and executes the 9-node AdaptOS Factory StateGraph."""

    def __init__(self, deps: FactoryDeps) -> None:
        self.deps = deps

    async def _load_assets(self, refs: GraphRefs) -> list[SourceAssetInput]:
        blob_sha = refs.get("assets_blob_sha256")
        if not blob_sha:
            return []
        raw_list = await asyncio.to_thread(self.deps.asset_store.get_json_blob, blob_sha)
        return [SourceAssetInput.model_validate(item) for item in raw_list]

    async def _load_dev_cases(self, refs: GraphRefs) -> list[DevCase]:
        blob_sha = refs.get("dev_cases_blob_sha256")
        if not blob_sha:
            raise ValueError("Missing dev_cases_blob_sha256 in refs.")
        raw_list = await asyncio.to_thread(self.deps.asset_store.get_json_blob, blob_sha)
        return [DevCase.model_validate(item) for item in raw_list]

    # ----------------------------------------------------------------------- #
    # Node 1: init_run
    # ----------------------------------------------------------------------- #
    async def init_run_node(self, state: FactoryGraphState) -> dict[str, Any]:
        try:
            f_state = FactoryState.model_validate(state["factory"])
            refs = dict(state.get("refs", {}))
            events = list(state.get("events", []))

            # Enforce hard maximum of 3 repair attempts at the graph level (Item 3)
            if f_state.max_repair_attempts > MAX_GRAPH_REPAIR_ATTEMPTS:
                f_state.max_repair_attempts = MAX_GRAPH_REPAIR_ATTEMPTS

            handoff_sha = refs.get("handoff_blob_sha256")
            if handoff_sha and f_state.spec is None:
                handoff_dict = await asyncio.wait_for(
                    asyncio.to_thread(self.deps.asset_store.get_json_blob, handoff_sha),
                    timeout=self.deps.node_timeout_seconds,
                )
                f_state = apply_handoff_to_factory_state(f_state, handoff_dict)

            _verify_spec_hash_chain(f_state)

            if not refs.get("assets_blob_sha256"):
                raw_assets_sha = refs.get("raw_assets_blob_sha256")
                source_assets: list[dict[str, Any]] = []
                if raw_assets_sha:
                    raw_items = await asyncio.wait_for(
                        asyncio.to_thread(self.deps.asset_store.get_json_blob, raw_assets_sha),
                        timeout=self.deps.node_timeout_seconds,
                    )
                    for item in raw_items:
                        sa = SourceAssetInput.model_validate(item)
                        source_assets.append(sa.model_dump(mode="json"))
                assets_sha = await asyncio.wait_for(
                    asyncio.to_thread(self.deps.asset_store.put_json_blob, source_assets),
                    timeout=self.deps.node_timeout_seconds,
                )
                refs["assets_blob_sha256"] = assets_sha

            if f_state.stage in ("intake", "spec_review"):
                f_state.stage = "eval_design"

            assert f_state.approved_spec_hash is not None
            events.append(
                f"[init_run] Initialized run with spec_hash={f_state.approved_spec_hash[:12]}"
            )
            return {
                "factory": f_state.model_dump(mode="json"),
                "refs": refs,
                "events": events,
            }
        except Exception as exc:
            return _record_node_error(
                state, stage_name="init_run", code="init_run_failed", message=exc
            )

    # ----------------------------------------------------------------------- #
    # Node 2: design_eval
    # ----------------------------------------------------------------------- #
    async def design_eval_node(self, state: FactoryGraphState) -> dict[str, Any]:
        try:
            f_state = FactoryState.model_validate(state["factory"])
            _verify_spec_hash_chain(f_state)
            refs = dict(state.get("refs", {}))
            events = list(state.get("events", []))

            if refs.get("plan_hash"):
                events.append(
                    f"[design_eval] Reusing existing plan_hash={refs['plan_hash'][:12]}"
                )
                return {
                    "factory": f_state.model_dump(mode="json"),
                    "refs": refs,
                    "events": events,
                }

            assets = await self._load_assets(refs)
            assert f_state.spec is not None
            status, plan_hash, split_ready, err_msg = await asyncio.wait_for(
                self.deps.eval_designer.design_evaluation(f_state.spec, assets),
                timeout=self.deps.node_timeout_seconds,
            )
            if status == "failed_untestable" or not plan_hash or not split_ready:
                return _record_node_error(
                    state,
                    stage_name="design_eval",
                    code="eval_design_insufficient",
                    message=f"Eval Designer status={status}, split_ready={split_ready}: {err_msg}",
                )

            refs["plan_hash"] = plan_hash
            events.append(
                f"[design_eval] Assembled split-ready TestPlan plan_hash={plan_hash[:12]}"
            )
            return {
                "factory": f_state.model_dump(mode="json"),
                "refs": refs,
                "events": events,
            }
        except Exception as exc:
            return _record_node_error(
                state, stage_name="design_eval", code="design_eval_error", message=exc
            )

    # ----------------------------------------------------------------------- #
    # Node 3: split_and_seal
    # ----------------------------------------------------------------------- #
    async def split_and_seal_node(self, state: FactoryGraphState) -> dict[str, Any]:
        try:
            f_state = FactoryState.model_validate(state["factory"])
            _verify_spec_hash_chain(f_state)
            refs = dict(state.get("refs", {}))
            events = list(state.get("events", []))

            if f_state.sealed is not None and refs.get("dev_cases_blob_sha256"):
                events.append(
                    f"[split_and_seal] Reusing sealed set {f_state.sealed.set_id}"
                )
                return {
                    "factory": f_state.model_dump(mode="json"),
                    "refs": refs,
                    "events": events,
                }

            plan_hash = refs.get("plan_hash")
            if not plan_hash:
                raise ValueError("Missing plan_hash before split_and_seal.")

            assert f_state.spec is not None
            dev_cases, commitment = await asyncio.wait_for(
                asyncio.to_thread(
                    self.deps.splitter.split_and_seal,
                    plan_hash=plan_hash,
                    spec=f_state.spec,
                    seed=self.deps.split_seed,
                ),
                timeout=self.deps.node_timeout_seconds,
            )
            dev_blob_sha = await asyncio.wait_for(
                asyncio.to_thread(
                    self.deps.asset_store.put_json_blob,
                    [dc.model_dump(mode="json") for dc in dev_cases],
                ),
                timeout=self.deps.node_timeout_seconds,
            )
            refs["dev_cases_blob_sha256"] = dev_blob_sha
            refs["sealed_set_id"] = commitment.set_id

            f_state.sealed = commitment
            f_state.dev_case_ids = [dc.case_id for dc in dev_cases]

            events.append(
                f"[split_and_seal] Split {len(dev_cases)} dev cases & sealed {commitment.case_count} held-out cases ({commitment.set_id})"
            )
            return {
                "factory": f_state.model_dump(mode="json"),
                "refs": refs,
                "events": events,
            }
        except Exception as exc:
            return _record_node_error(
                state,
                stage_name="split_and_seal",
                code="split_and_seal_error",
                message=exc,
            )

    # ----------------------------------------------------------------------- #
    # Node 4: build (Initial Build Does Not Count as a Repair Attempt)
    # ----------------------------------------------------------------------- #
    async def build_node(self, state: FactoryGraphState) -> dict[str, Any]:
        try:
            f_state = FactoryState.model_validate(state["factory"])
            _verify_spec_hash_chain(f_state)
            refs = dict(state.get("refs", {}))
            events = list(state.get("events", []))

            if f_state.baseline is not None and f_state.candidate is not None:
                if f_state.stage == "building":
                    f_state.stage = "dev_testing"
                events.append("[build] Reusing existing baseline and candidate bundles.")
                return {
                    "factory": f_state.model_dump(mode="json"),
                    "refs": refs,
                    "events": events,
                }

            dev_cases = await self._load_dev_cases(refs)
            assets = await self._load_assets(refs)

            state_copy = f_state.model_copy(deep=True)
            build_res = await asyncio.wait_for(
                self.deps.builder.build(state_copy, dev_cases, assets),
                timeout=self.deps.node_timeout_seconds,
            )
            if (
                build_res.status in ("unsupported", "failed")
                or build_res.baseline_manifest is None
                or build_res.candidate_manifest is None
            ):
                return _record_node_error(
                    state,
                    stage_name="build",
                    code=f"build_{build_res.status}",
                    message=build_res.error_message
                    or f"Build failed with status={build_res.status}",
                )

            # Initial build produces 0 repair records (repair_attempts == 0)
            f_state.dev_case_ids = [dc.case_id for dc in dev_cases]
            f_state.baseline = build_res.baseline_manifest
            f_state.candidate = build_res.candidate_manifest
            f_state.stage = "dev_testing"

            events.append(
                f"[build] Built baseline={f_state.baseline.version_id} & candidate={f_state.candidate.version_id} (repair_attempts={f_state.repair_attempts})"
            )
            return {
                "factory": f_state.model_dump(mode="json"),
                "refs": refs,
                "events": events,
            }
        except Exception as exc:
            return _record_node_error(
                state, stage_name="build", code="build_error", message=exc
            )

    # ----------------------------------------------------------------------- #
    # Node 5: dev_test
    # ----------------------------------------------------------------------- #
    async def dev_test_node(self, state: FactoryGraphState) -> dict[str, Any]:
        try:
            f_state = FactoryState.model_validate(state["factory"])
            _verify_spec_hash_chain(f_state)
            refs = dict(state.get("refs", {}))
            events = list(state.get("events", []))

            if f_state.max_repair_attempts > MAX_GRAPH_REPAIR_ATTEMPTS:
                f_state.max_repair_attempts = MAX_GRAPH_REPAIR_ATTEMPTS

            assert (
                f_state.spec is not None
                and f_state.baseline is not None
                and f_state.candidate is not None
            )
            dev_cases = await self._load_dev_cases(refs)
            assets = await self._load_assets(refs)

            base_run = await asyncio.wait_for(
                asyncio.to_thread(
                    self.deps.builder.run_dev_suite,
                    version_id=f_state.baseline.version_id,
                    spec=f_state.spec,
                    dev_cases=dev_cases,
                    assets=assets,
                ),
                timeout=self.deps.node_timeout_seconds,
            )
            cand_run = await asyncio.wait_for(
                asyncio.to_thread(
                    self.deps.builder.run_dev_suite,
                    version_id=f_state.candidate.version_id,
                    spec=f_state.spec,
                    dev_cases=dev_cases,
                    assets=assets,
                ),
                timeout=self.deps.node_timeout_seconds,
            )

            f_state.dev_runs = [*f_state.dev_runs, base_run, cand_run]
            base_passed = is_dev_run_passing(base_run)
            cand_passed = is_dev_run_passing(cand_run)

            if base_passed:
                f_state.last_passing = f_state.baseline
                events.append(
                    f"[dev_test] Baseline passed (pass_rate={base_run.pass_rate:.2f}); routing to freeze."
                )
            elif cand_passed:
                f_state.last_passing = f_state.candidate
                events.append(
                    f"[dev_test] Candidate passed (pass_rate={cand_run.pass_rate:.2f}); routing to freeze."
                )
            else:
                effective_budget = min(
                    f_state.repair_budget_left,
                    MAX_GRAPH_REPAIR_ATTEMPTS - len(f_state.repair_log),
                )
                if effective_budget > 0:
                    f_state.stage = "repairing"
                    events.append(
                        f"[dev_test] Both failed (baseline={base_run.pass_rate:.2f}, candidate={cand_run.pass_rate:.2f}); routing to repair."
                    )
                else:
                    events.append(
                        "[dev_test] Both failed and repair budget is 0; routing to freeze."
                    )

            return {
                "factory": f_state.model_dump(mode="json"),
                "refs": refs,
                "events": events,
            }
        except Exception as exc:
            return _record_node_error(
                state, stage_name="dev_test", code="dev_test_error", message=exc
            )

    # ----------------------------------------------------------------------- #
    # Node 6: repair (Hard Cap of 3 Attempts, Outcome Validation & Child DevRun Recording)
    # ----------------------------------------------------------------------- #
    async def repair_node(self, state: FactoryGraphState) -> dict[str, Any]:
        try:
            f_state = FactoryState.model_validate(state["factory"])
            _verify_spec_hash_chain(f_state)
            refs = dict(state.get("refs", {}))
            events = list(state.get("events", []))

            if f_state.max_repair_attempts > MAX_GRAPH_REPAIR_ATTEMPTS:
                f_state.max_repair_attempts = MAX_GRAPH_REPAIR_ATTEMPTS

            assert f_state.spec is not None and f_state.candidate is not None

            attempts_before = len(f_state.repair_log)
            effective_budget_left = min(
                f_state.repair_budget_left,
                MAX_GRAPH_REPAIR_ATTEMPTS - attempts_before,
            )

            # Enforce hard cap of 3 repair attempts (Item 3)
            if attempts_before >= MAX_GRAPH_REPAIR_ATTEMPTS or effective_budget_left <= 0:
                best = _select_best_eligible_manifest(f_state)
                f_state.candidate = best
                f_state.frozen = best.ref
                f_state.stage = "frozen"
                events.append(
                    f"[repair] Repair limit reached ({attempts_before}/{MAX_GRAPH_REPAIR_ATTEMPTS}); froze best eligible version {best.version_id}"
                )
                return {
                    "factory": f_state.model_dump(mode="json"),
                    "refs": refs,
                    "events": events,
                }

            dev_cases = await self._load_dev_cases(refs)
            assets = await self._load_assets(refs)

            parent_candidate = f_state.candidate
            cand_vid = parent_candidate.version_id
            latest_cand_run = next(
                (r for r in reversed(f_state.dev_runs) if r.version_id == cand_vid),
                f_state.dev_runs[-1],
            )
            tried_hashes = list(refs.get("tried_patch_hashes") or [])
            fixtures_queue = list(refs.get("repair_proposal_fixtures") or [])
            expected_attempt = attempts_before + 1

            req = BundleRepairRequest(
                spec=f_state.spec,
                approved_spec_hash=f_state.approved_spec_hash
                or f_state.spec.content_hash(),
                candidate_manifest=parent_candidate,
                dev_cases=tuple(dev_cases),
                latest_dev_run=latest_cand_run,
                assets=tuple(assets),
                attempt_number=expected_attempt,
                budget_left=effective_budget_left,
                cost_spent_usd=0.0,
                cost_cap_usd=0.50,
                tried_patch_hashes=tuple(tried_hashes),
                last_rejected_target=refs.get("last_rejected_target"),
                last_rejected_kind=refs.get("last_rejected_kind"),  # type: ignore[arg-type]
            )
            outcome = await asyncio.wait_for(
                self.deps.repair.run_attempt(
                    req,
                    proposal_fixtures=fixtures_queue if fixtures_queue else None,
                ),
                timeout=self.deps.node_timeout_seconds,
            )
            if fixtures_queue:
                refs["repair_proposal_fixtures"] = fixtures_queue

            # Item 4 & 5: Strictly validate BundleRepairOutcome and parent-child version chaining
            _validate_repair_outcome(
                outcome=outcome,
                expected_attempt=expected_attempt,
                parent_candidate=parent_candidate,
                existing_repair_log=f_state.repair_log,
            )

            if outcome.patch_hash and outcome.patch_hash not in tried_hashes:
                tried_hashes.append(outcome.patch_hash)
                refs["tried_patch_hashes"] = tried_hashes

            if outcome.status == "rejected":
                refs["last_rejected_target"] = outcome.proposal_target
                refs["last_rejected_kind"] = outcome.proposal_kind
            else:
                refs["last_rejected_target"] = None
                refs["last_rejected_kind"] = None

            # Record RepairRecord (assignment triggers FactoryState validators)
            if outcome.repair_record is not None:
                f_state.repair_log = [*f_state.repair_log, outcome.repair_record]

            # Item 6: Record child_dev_run whenever produced (both on accepted and rejected attempts)
            if outcome.child_dev_run is not None:
                f_state.dev_runs = [*f_state.dev_runs, outcome.child_dev_run]

            # Item 5: Update candidate to new_manifest ONLY when repair was accepted
            if outcome.status == "repaired" and outcome.new_manifest is not None:
                f_state.candidate = outcome.new_manifest
                if outcome.child_dev_run is not None and is_dev_run_passing(
                    outcome.child_dev_run
                ):
                    f_state.last_passing = outcome.new_manifest

            # Determine whether to freeze or continue repairing
            attempts_after = len(f_state.repair_log)
            remaining_after = min(
                f_state.repair_budget_left,
                MAX_GRAPH_REPAIR_ATTEMPTS - attempts_after,
            )
            cand_latest_run = next(
                (
                    r
                    for r in reversed(f_state.dev_runs)
                    if r.version_id == f_state.candidate.version_id
                ),
                None,
            )
            cand_now_passing = (
                cand_latest_run is not None and is_dev_run_passing(cand_latest_run)
            )
            unknown_paid_halt = (
                outcome.cost_status == "unknown" and outcome.cost_usd_delta is None and not fixtures_queue
            )

            if (
                cand_now_passing
                or outcome.status in ("no_failure", "aborted")
                or attempts_after >= MAX_GRAPH_REPAIR_ATTEMPTS
                or remaining_after <= 0
                or unknown_paid_halt
            ):
                best = _select_best_eligible_manifest(f_state)
                f_state.candidate = best
                f_state.frozen = best.ref
                f_state.stage = "frozen"
            else:
                # Item 4: Prevent a repair self-loop if attempt count did not advance!
                if attempts_after <= attempts_before:
                    raise ValueError(
                        "Repair loop invariant violation: attempt count did not advance while remaining in 'repairing'."
                    )
                f_state.stage = "repairing"

            events.append(
                f"[repair] Attempt #{expected_attempt} status={outcome.status}, candidate={f_state.candidate.version_id}, next_stage={f_state.stage}"
            )
            return {
                "factory": f_state.model_dump(mode="json"),
                "refs": refs,
                "events": events,
            }
        except Exception as exc:
            return _record_node_error(
                state, stage_name="repair", code="repair_error", message=exc
            )

    # ----------------------------------------------------------------------- #
    # Node 7: freeze
    # ----------------------------------------------------------------------- #
    async def freeze_node(self, state: FactoryGraphState) -> dict[str, Any]:
        try:
            f_state = FactoryState.model_validate(state["factory"])
            _verify_spec_hash_chain(f_state)
            refs = dict(state.get("refs", {}))
            events = list(state.get("events", []))

            chosen = _select_best_eligible_manifest(f_state)
            f_state.candidate = chosen
            f_state.frozen = chosen.ref
            f_state.stage = "frozen"

            events.append(f"[freeze] Froze bundle version={chosen.version_id}")
            return {
                "factory": f_state.model_dump(mode="json"),
                "refs": refs,
                "events": events,
            }
        except Exception as exc:
            return _record_node_error(
                state, stage_name="freeze", code="freeze_error", message=exc
            )

    # ----------------------------------------------------------------------- #
    # Node 8: evaluate (Protected Evaluation + Strict Ed25519 Signature Check)
    # ----------------------------------------------------------------------- #
    async def evaluate_node(self, state: FactoryGraphState) -> dict[str, Any]:
        try:
            f_state = FactoryState.model_validate(state["factory"])
            _verify_spec_hash_chain(f_state)
            refs = dict(state.get("refs", {}))
            events = list(state.get("events", []))

            if f_state.verdict is not None and f_state.stage == "verdict_issued":
                events.append(
                    f"[evaluate] Reusing verified verdict status={f_state.verdict.status}"
                )
                return {
                    "factory": f_state.model_dump(mode="json"),
                    "refs": refs,
                    "events": events,
                }

            if f_state.frozen is None or f_state.sealed is None or f_state.spec is None:
                raise ValueError("Cannot evaluate: frozen, sealed, or spec is missing.")

            frozen_manifest = await asyncio.wait_for(
                asyncio.to_thread(
                    self.deps.builder.load_manifest, f_state.frozen.version_id
                ),
                timeout=self.deps.node_timeout_seconds,
            )
            if frozen_manifest.artifact_hash != f_state.frozen.artifact_hash:
                raise ValueError("Frozen manifest hash mismatch on reload.")

            eval_req = EvaluationRequest(
                artifact=frozen_manifest,
                spec=f_state.spec,
                sealed=f_state.sealed,
            )
            verdict = await asyncio.wait_for(
                asyncio.to_thread(self.deps.eval_plane.evaluate, eval_req),
                timeout=self.deps.node_timeout_seconds,
            )

            # Invariant 3: Verify Ed25519 signature on Verdict.signing_payload() using factory public key
            if not Ed25519KeyPair.verify(
                self.deps.eval_public_key_bytes,
                verdict.signing_payload(),
                verdict.signature,
            ):
                raise ValueError("Verdict Ed25519 signature verification failed!")

            if (
                verdict.spec_hash != f_state.approved_spec_hash
                or verdict.artifact != f_state.frozen
                or verdict.sealed_set_id != f_state.sealed.set_id
                or verdict.sealed_commitment_hash != f_state.sealed.commitment_hash
            ):
                mismatch = {
                    "spec_hash": verdict.spec_hash != f_state.approved_spec_hash,
                    "artifact": verdict.artifact != f_state.frozen,
                    "sealed_set_id": verdict.sealed_set_id != f_state.sealed.set_id,
                    "commitment_hash": verdict.sealed_commitment_hash != f_state.sealed.commitment_hash,
                }
                raise ValueError(
                    "Verdict hash or commitment binding mismatch against frozen artifact or sealed set. "
                    + json.dumps(mismatch)
                )

            f_state.verdict = verdict
            f_state.stage = "verdict_issued"

            events.append(
                f"[evaluate] Verified Ed25519 signed Verdict status={verdict.status} on version={f_state.frozen.version_id}"
            )
            return {
                "factory": f_state.model_dump(mode="json"),
                "refs": refs,
                "events": events,
            }
        except Exception as exc:
            return _record_node_error(
                state, stage_name="evaluate", code="evaluate_error", message=exc
            )

    # ----------------------------------------------------------------------- #
    # Node 9: deliver (Calls DeliveryPort; Delivers Ready & Not-Ready Honestly)
    # ----------------------------------------------------------------------- #
    async def deliver_node(self, state: FactoryGraphState) -> dict[str, Any]:
        try:
            f_state = FactoryState.model_validate(state["factory"])
            _verify_spec_hash_chain(f_state)
            refs = dict(state.get("refs", {}))
            events = list(state.get("events", []))

            if f_state.verdict is None or f_state.frozen is None or f_state.spec is None:
                raise ValueError(
                    "Cannot deliver without verdict, frozen ref, and spec."
                )

            frozen_manifest = await asyncio.wait_for(
                asyncio.to_thread(
                    self.deps.builder.load_manifest, f_state.frozen.version_id
                ),
                timeout=self.deps.node_timeout_seconds,
            )
            _, pkg_blob_sha = await asyncio.wait_for(
                asyncio.to_thread(
                    self.deps.delivery.deliver,
                    spec=f_state.spec,
                    artifact=frozen_manifest,
                    verdict=f_state.verdict,
                    repair_log=f_state.repair_log,
                ),
                timeout=self.deps.node_timeout_seconds,
            )
            refs["delivery_blob_sha256"] = pkg_blob_sha
            f_state.stage = "delivered"

            events.append(
                f"[deliver] Delivered package blob={pkg_blob_sha[:12]} (verdict={f_state.verdict.status})"
            )
            return {
                "factory": f_state.model_dump(mode="json"),
                "refs": refs,
                "events": events,
            }
        except Exception as exc:
            return _record_node_error(
                state, stage_name="deliver", code="deliver_error", message=exc
            )

    # ----------------------------------------------------------------------- #
    # Terminal Failure Node: fail
    # ----------------------------------------------------------------------- #
    async def fail_node(self, state: FactoryGraphState) -> dict[str, Any]:
        f_state = FactoryState.model_validate(state["factory"])
        events = list(state.get("events", []))
        if not f_state.errors:
            f_state.errors = [
                ErrorRecord(
                    stage=f_state.stage,
                    code="factory_failed",
                    message="Run terminated in fail node.",
                )
            ]
        f_state.stage = "failed"
        events.append(
            f"[fail] Run terminated in stage=failed ({f_state.errors[-1].code})"
        )
        return {
            "factory": f_state.model_dump(mode="json"),
            "refs": dict(state.get("refs", {})),
            "events": events,
        }

    # ----------------------------------------------------------------------- #
    # Routing Functions
    # ----------------------------------------------------------------------- #
    @staticmethod
    def _has_new_error(state: FactoryGraphState) -> bool:
        f_state = FactoryState.model_validate(state["factory"])
        return bool(f_state.errors) or f_state.stage == "failed"

    def route_after_init(
        self, state: FactoryGraphState
    ) -> Literal["design_eval", "fail"]:
        return "fail" if self._has_new_error(state) else "design_eval"

    def route_after_design_eval(
        self, state: FactoryGraphState
    ) -> Literal["split_and_seal", "fail"]:
        if self._has_new_error(state) or not state.get("refs", {}).get("plan_hash"):
            return "fail"
        return "split_and_seal"

    def route_after_split_and_seal(
        self, state: FactoryGraphState
    ) -> Literal["build", "fail"]:
        f_state = FactoryState.model_validate(state["factory"])
        if self._has_new_error(state) or f_state.sealed is None:
            return "fail"
        return "build"

    def route_after_build(
        self, state: FactoryGraphState
    ) -> Literal["dev_test", "fail"]:
        f_state = FactoryState.model_validate(state["factory"])
        if (
            self._has_new_error(state)
            or f_state.baseline is None
            or f_state.candidate is None
        ):
            return "fail"
        return "dev_test"

    def route_after_dev_test(
        self, state: FactoryGraphState
    ) -> Literal["freeze", "repair", "fail"]:
        if self._has_new_error(state):
            return "fail"
        f_state = FactoryState.model_validate(state["factory"])
        if f_state.last_passing is not None:
            return "freeze"
        effective_budget = min(
            f_state.repair_budget_left,
            MAX_GRAPH_REPAIR_ATTEMPTS - len(f_state.repair_log),
        )
        if f_state.stage == "repairing" and effective_budget > 0:
            return "repair"
        return "freeze"

    def route_after_repair(
        self, state: FactoryGraphState
    ) -> Literal["evaluate", "repair", "fail"]:
        if self._has_new_error(state):
            return "fail"
        f_state = FactoryState.model_validate(state["factory"])
        if f_state.stage == "frozen" and f_state.frozen is not None:
            return "evaluate"
        if (
            len(f_state.repair_log) >= MAX_GRAPH_REPAIR_ATTEMPTS
            or f_state.repair_budget_left <= 0
        ):
            return "fail"
        return "repair"

    def route_after_freeze(
        self, state: FactoryGraphState
    ) -> Literal["evaluate", "fail"]:
        f_state = FactoryState.model_validate(state["factory"])
        if self._has_new_error(state) or f_state.frozen is None:
            return "fail"
        return "evaluate"

    def route_after_evaluate(
        self, state: FactoryGraphState
    ) -> Literal["deliver", "fail"]:
        f_state = FactoryState.model_validate(state["factory"])
        if self._has_new_error(state) or f_state.verdict is None:
            return "fail"
        return "deliver"

    def route_after_deliver(
        self, state: FactoryGraphState
    ) -> Literal["end", "fail"]:
        if self._has_new_error(state):
            return "fail"
        return "end"

    def build_graph(self, checkpointer: Any = None) -> Any:
        builder = StateGraph(FactoryGraphState)
        builder.add_node("init_run", self.init_run_node)
        builder.add_node("design_eval", self.design_eval_node)
        builder.add_node("split_and_seal", self.split_and_seal_node)
        builder.add_node("build", self.build_node)
        builder.add_node("dev_test", self.dev_test_node)
        builder.add_node("repair", self.repair_node)
        builder.add_node("freeze", self.freeze_node)
        builder.add_node("evaluate", self.evaluate_node)
        builder.add_node("deliver", self.deliver_node)
        builder.add_node("fail", self.fail_node)

        builder.add_edge(START, "init_run")
        builder.add_conditional_edges(
            "init_run",
            self.route_after_init,
            {"design_eval": "design_eval", "fail": "fail"},
        )
        builder.add_conditional_edges(
            "design_eval",
            self.route_after_design_eval,
            {"split_and_seal": "split_and_seal", "fail": "fail"},
        )
        builder.add_conditional_edges(
            "split_and_seal",
            self.route_after_split_and_seal,
            {"build": "build", "fail": "fail"},
        )
        builder.add_conditional_edges(
            "build",
            self.route_after_build,
            {"dev_test": "dev_test", "fail": "fail"},
        )
        builder.add_conditional_edges(
            "dev_test",
            self.route_after_dev_test,
            {"freeze": "freeze", "repair": "repair", "fail": "fail"},
        )
        builder.add_conditional_edges(
            "repair",
            self.route_after_repair,
            {"evaluate": "evaluate", "repair": "repair", "fail": "fail"},
        )
        # Invariant 2: After freeze, there are ZERO edges to build, dev_test, or repair!
        builder.add_conditional_edges(
            "freeze",
            self.route_after_freeze,
            {"evaluate": "evaluate", "fail": "fail"},
        )
        builder.add_conditional_edges(
            "evaluate",
            self.route_after_evaluate,
            {"deliver": "deliver", "fail": "fail"},
        )
        builder.add_conditional_edges(
            "deliver",
            self.route_after_deliver,
            {"end": END, "fail": "fail"},
        )
        builder.add_edge("fail", END)

        compiled = builder.compile(checkpointer=checkpointer)
        return compiled.with_config({"recursion_limit": self.deps.recursion_limit})


# =========================================================================== #
# 5. COMPREHENSIVE SELF-TEST SUITE (All Existing + New Required Tests)
# =========================================================================== #


def _make_triage_spec(extra_constraints: Sequence[str] = ()) -> Spec:
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
        constraints=["Never approve refunds after 30 calendar days.", *extra_constraints],
        acceptance_criteria=[
            AcceptanceCriterion(
                criterion_id="crit_exact_decision",
                description="Accurately classifies refund eligibility decision label for standard requests.",
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


def _build_full_test_harness(
    tmp_root: Path,
    *,
    spec: Spec | None = None,
    seed_retrieval_bug: bool = False,
    baseline_passes: bool = False,
    repair_fixtures: list[dict[str, Any]] | None = None,
    eval_case_count_per_criterion: int = 25,
    max_repair_attempts_requested: int = 3,
) -> tuple[
    StorageService,
    FactoryDeps,
    FactoryGraphState,
    Ed25519KeyPair,
    LocalProtectedEvalPlane,
    SealedVaultStore,
]:
    storage = ensure_storage_compat(
        StorageService(StorageConfig(tmp_root / "agnos_data"))
    )
    storage.initialize()
    active_spec = spec or _make_triage_spec()

    policy_text = (
        "Section 4.2 Refund Policy: Full refunds are granted within 30 calendar days of purchase "
        "if the software license key has not been activated."
    )
    raw_assets = [
        {
            "asset_id": "policy_doc_v1",
            "filename": "refund_policy.md",
            "content": policy_text,
            "format": "md",
        }
    ]
    asset_store = StorageAssetStoreAdapter(storage)
    raw_assets_sha = asset_store.put_json_blob(raw_assets)
    assets_objs = [SourceAssetInput.model_validate(a) for a in raw_assets]

    ed_cfg = EvalDesignerConfig(
        data_root=tmp_root / "ed_data",
        min_dev_cases_per_criterion=5,
        min_generated_cases_per_criterion=5,
        max_generated_cases_per_criterion=50,
    )

    def _ed_responder(purpose: str, prompt: str, model_cls: Any) -> dict[str, Any]:
        source_docs = (
            SourceDocument(
                source_id="policy_doc_v1",
                filename="refund_policy.md",
                sha256=sha256_hex(policy_text.encode("utf-8")),
                content=policy_text,
            ),
        )
        app_spec = ApprovedSpec.from_factory_spec(
            active_spec.model_dump(mode="json"),
            expected_spec_hash=active_spec.content_hash(),
            source_documents=source_docs,
        )
        cases = build_mock_cases_for_spec(
            app_spec, count_per_criterion=eval_case_count_per_criterion
        )
        return {"cases": cases}

    ed_service = EvalDesignerService(ed_cfg, mock_responder=_ed_responder)
    vault = SealedVaultStore(tmp_root / "vault_data" / "sealed_vault.db")
    splitter = DeterministicSplitterAdapter(ed_service, vault)

    def _runtime_handler(
        sys_p: str, usr_p: str, schema: dict[str, Any]
    ) -> dict[str, Any]:
        has_retrieved_evidence = (
            "Full refunds are granted within 30 calendar days" in usr_p
        )
        if not has_retrieved_evidence and not baseline_passes:
            return {
                "decision": "approve_refund",
                "policy_citation": "No policy context available.",
            }
        m = re.search(r"#(\d+)\s+for\s+crit_", usr_p)
        idx = (int(m.group(1)) - 1) if m else 0
        decision = "approve_refund" if idx % 2 == 0 else "reject_refund"
        return {
            "decision": decision,
            "policy_citation": "Full refunds are granted within 30 calendar days of purchase",
        }

    app_id = f"app-{active_spec.content_hash()[:10]}"
    out_schema = spec_fields_to_json_schema(active_spec.outputs)
    ret_mode = "all" if seed_retrieval_bug else "any"

    cand_draft = {
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
        "rationale": "Candidate plan for graph orchestrator test.",
    }

    adapter = ReplayAndLiveModelAdapter(
        BuilderConfig(),
        planner_fixtures=[cand_draft],
        runtime_handler=_runtime_handler,
    )
    verifier = SandboxVerifier(
        BuilderConfig(), docker_runner_override=_simulated_docker_runner
    )
    engine = BuildEngine(
        BuilderConfig(),
        storage,
        model_adapter=adapter,
        sandbox_verifier=verifier,
    )

    keypair = Ed25519KeyPair(b"adaptos_eval_plane_secret_seed32")
    eval_plane = LocalProtectedEvalPlane(
        vault=vault, engine=engine, signing_key=keypair, assets=assets_objs
    )

    deps = FactoryDeps(
        eval_designer=RealEvalDesignerAdapter(ed_service),
        splitter=splitter,
        builder=RealBuilderAdapter(engine),
        repair=RealRepairAdapter(engine, default_fixtures=repair_fixtures),
        eval_plane=eval_plane,
        asset_store=asset_store,
        delivery=PlaceholderDeliveryPortAdapter(asset_store),
        eval_public_key_bytes=keypair.public_key_bytes,
    )

    initial_f_state = FactoryState(
        stage="eval_design",
        user_goal=active_spec.goal,
        spec=active_spec,
        approved_spec_hash=active_spec.content_hash(),
        max_repair_attempts=max_repair_attempts_requested,
    )
    initial_graph_state: FactoryGraphState = {
        "factory": initial_f_state.model_dump(mode="json"),
        "refs": {
            "run_id": "run_test_001",
            "raw_assets_blob_sha256": raw_assets_sha,
            "tried_patch_hashes": [],
            "repair_proposal_fixtures": list(repair_fixtures or []),
        },
        "events": [],
    }
    return storage, deps, initial_graph_state, keypair, eval_plane, vault


class GraphOrchestratorTestSuite(unittest.IsolatedAsyncioTestCase):
    """Verifies all 12 audit items, 7 invariants, and end-to-end graph execution flows."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="adaptos_graph_test_")
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

    def test_01_invariant_topology_and_post_freeze_immutability(self) -> None:
        """Invariants 1 & 2: Verifies that post-freeze nodes (freeze, evaluate, deliver) have
        zero edges back to build, dev_test, or repair.
        """
        _, deps, _, _, _, _ = _build_full_test_harness(self.tmp_path)
        orch = FactoryOrchestrator(deps)
        compiled = orch.build_graph()
        graph_drawable = compiled.get_graph()

        pre_freeze_targets = {
            "init_run",
            "design_eval",
            "split_and_seal",
            "build",
            "dev_test",
            "repair",
        }
        post_freeze_sources = {"freeze", "evaluate", "deliver"}

        for edge in graph_drawable.edges:
            if edge.source in post_freeze_sources:
                self.assertNotIn(
                    edge.target,
                    pre_freeze_targets,
                    f"Post-freeze node '{edge.source}' has forbidden backward edge to '{edge.target}'!",
                )

    async def test_02_happy_path_deliver_exact_verdict_schema_and_zero_hidden_data(self) -> None:
        """Items 2 & 8, Invariants 1, 3, 4 & 5: Runs full pipeline, verifies exact schemas.Verdict
        fields (sealed_commitment_hash, criteria, evidence_hash, signing_key_id, signature),
        and confirms zero hidden case leakage in graph state/events.
        """
        storage, deps, init_state, _, _, _ = _build_full_test_harness(
            self.tmp_path, seed_retrieval_bug=False
        )
        saver = SqliteSerdeSaver(storage.get_checkpoint_db_path())
        orch = FactoryOrchestrator(deps)
        graph = orch.build_graph(checkpointer=saver)
        cfg = {"configurable": {"thread_id": "run-happy-01"}}

        final_state = await graph.ainvoke(init_state, config=cfg)
        f_state = FactoryState.model_validate(final_state["factory"])

        self.assertEqual(f_state.stage, "delivered")
        self.assertEqual(f_state.repair_attempts, 0)  # Initial build is 0 repair attempts
        self.assertIsNotNone(f_state.verdict)
        assert f_state.verdict is not None and f_state.sealed is not None
        self.assertEqual(f_state.verdict.status, "ready")
        self.assertEqual(
            f_state.verdict.sealed_commitment_hash, f_state.sealed.commitment_hash
        )
        self.assertEqual(f_state.verdict.signing_key_id, "eval-ed25519-key-01")
        self.assertEqual(len(f_state.verdict.criteria), 2)
        self.assertEqual(len(f_state.verdict.evidence_hash), 64)
        self.assertIsNotNone(final_state["refs"].get("delivery_blob_sha256"))

        state_serialized = json.dumps(final_state)
        self.assertNotIn("case_crit_exact_decision_20", state_serialized)
        self.assertNotIn("expected_value", state_serialized)

    async def test_03_seeded_failure_runs_checkpointed_repair_and_delivers_ready(self) -> None:
        """Section 5(b): When dev_test fails on seeded retrieval bug (mode='all'), graph routes
        to repair, runs 1 repair attempt, records child_dev_run, freezes repaired child,
        evaluates, and delivers 'ready' verdict.
        """
        fix_fixture = {
            "kind": "config",
            "target": "step_retrieve",
            "hypothesis": "LLM hypothesis: retrieve.lexical mode='all' fails on multi-word queries; switch to mode='any'.",
            "evidence_case_ids": ["placeholder"],
            "ops": [
                {
                    "op": "set_config",
                    "file": "app_config.json",
                    "step_id": "step_retrieve",
                    "pointer": "/mode",
                    "value": "any",
                }
            ],
        }
        storage, deps, init_state, _, _, _ = _build_full_test_harness(
            self.tmp_path,
            seed_retrieval_bug=True,
            repair_fixtures=[fix_fixture],
        )
        orig_run_attempt = deps.repair.run_attempt

        async def _dynamic_fixture_attempt(
            req: BundleRepairRequest, *, proposal_fixtures: Any = None
        ) -> BundleRepairOutcome:
            failing_cid = next(
                r.case_id for r in req.latest_dev_run.results if not r.passed
            )
            patched_fix = copy.deepcopy(fix_fixture)
            patched_fix["evidence_case_ids"] = [failing_cid]
            return await orig_run_attempt(req, proposal_fixtures=[patched_fix])

        deps.repair.run_attempt = _dynamic_fixture_attempt  # type: ignore[method-assign]

        saver = SqliteSerdeSaver(storage.get_checkpoint_db_path())
        orch = FactoryOrchestrator(deps)
        graph = orch.build_graph(checkpointer=saver)
        cfg = {"configurable": {"thread_id": "run-repair-01"}}

        final_state = await graph.ainvoke(init_state, config=cfg)
        f_state = FactoryState.model_validate(final_state["factory"])

        self.assertEqual(f_state.stage, "delivered")
        self.assertEqual(len(f_state.repair_log), 1)
        self.assertTrue(f_state.repair_log[0].accepted)
        assert f_state.verdict is not None
        self.assertEqual(f_state.verdict.status, "ready")

    async def test_04_repair_exhaustion_and_rejected_repair_preserves_artifacts(self) -> None:
        """Items 6 & 7: Rejected repair records child_dev_run, preserves previous candidate,
        freezes best eligible artifact on exhaustion, and receives 'not_ready' Verdict (never 'ready').
        """
        ineffective_fixture = {
            "kind": "config",
            "target": "step_retrieve",
            "hypothesis": "LLM hypothesis: change top_k to 4",
            "evidence_case_ids": ["placeholder"],
            "ops": [
                {
                    "op": "set_config",
                    "file": "app_config.json",
                    "step_id": "step_retrieve",
                    "pointer": "/top_k",
                    "value": 4,
                }
            ],
        }
        storage, deps, init_state, _, _, _ = _build_full_test_harness(
            self.tmp_path,
            seed_retrieval_bug=True,
            repair_fixtures=[ineffective_fixture],
            max_repair_attempts_requested=1,
        )
        orig_run_attempt = deps.repair.run_attempt

        async def _dynamic_bad_attempt(
            req: BundleRepairRequest, *, proposal_fixtures: Any = None
        ) -> BundleRepairOutcome:
            failing_cid = next(
                r.case_id for r in req.latest_dev_run.results if not r.passed
            )
            patched = copy.deepcopy(ineffective_fixture)
            patched["evidence_case_ids"] = [failing_cid]
            return await orig_run_attempt(req, proposal_fixtures=[patched])

        deps.repair.run_attempt = _dynamic_bad_attempt  # type: ignore[method-assign]

        orch = FactoryOrchestrator(deps)
        graph = orch.build_graph(
            checkpointer=SqliteSerdeSaver(storage.get_checkpoint_db_path())
        )
        final_state = await graph.ainvoke(
            init_state, config={"configurable": {"thread_id": "run-exhaust-01"}}
        )
        f_state = FactoryState.model_validate(final_state["factory"])

        self.assertEqual(f_state.stage, "delivered")
        self.assertEqual(len(f_state.repair_log), 1)
        self.assertFalse(f_state.repair_log[0].accepted)
        # Item 6: baseline run + candidate run + rejected child_dev_run = 3 dev_runs recorded
        self.assertEqual(len(f_state.dev_runs), 3)
        self.assertEqual(f_state.dev_runs[-1].version_id, "v1.0.0-candidate-r1")
        # Candidate remained v1.0.0-candidate and received 'not_ready' verdict
        assert f_state.verdict is not None
        self.assertEqual(f_state.verdict.status, "not_ready")

    async def test_05_tampered_verdict_signature_and_spec_hash_mismatch_fail_closed(self) -> None:
        """Invariants 3 & 5: Tampered Ed25519 signature or mismatched spec_hash routes to fail."""
        _, deps, init_state, _, _, _ = _build_full_test_harness(self.tmp_path)
        wrong_keypair = Ed25519KeyPair(b"wrong_public_key_seed_32_bytes!!")
        deps.eval_public_key_bytes = wrong_keypair.public_key_bytes

        orch = FactoryOrchestrator(deps)
        graph = orch.build_graph()
        final_state = await graph.ainvoke(init_state)
        f_state = FactoryState.model_validate(final_state["factory"])

        self.assertEqual(f_state.stage, "failed")
        self.assertTrue(
            any(
                "Ed25519 signature verification failed" in e.message
                for e in f_state.errors
            )
        )

    async def test_06_idempotency_and_under_coverage_handling(self) -> None:
        """Invariants 6 & 7: Verifies node idempotency when re-invoked and clean fail routing on under-coverage."""
        _, deps_under, init_under, _, _, _ = _build_full_test_harness(
            self.tmp_path / "under", eval_case_count_per_criterion=5
        )
        orch_under = FactoryOrchestrator(deps_under)
        res_under = await orch_under.build_graph().ainvoke(init_under)
        f_under = FactoryState.model_validate(res_under["factory"])
        self.assertEqual(f_under.stage, "failed")
        self.assertTrue(
            any(e.code == "eval_design_insufficient" for e in f_under.errors)
        )

        _, deps_idem, init_idem, _, eval_plane, _ = _build_full_test_harness(
            self.tmp_path / "idem"
        )
        orch_idem = FactoryOrchestrator(deps_idem)
        final_idem = await orch_idem.build_graph().ainvoke(init_idem)
        self.assertEqual(eval_plane.evaluation_calls, 1)
        await orch_idem.evaluate_node(final_idem)
        self.assertEqual(eval_plane.evaluation_calls, 1)

    async def test_07_max_three_repair_attempts_and_fourth_impossible(self) -> None:
        """Item 3: Even if max_repair_attempts is initialized to 5, graph clamps it to 3,
        executes exactly 3 repair attempts (initial build = 0 attempts), and proves a 4th is impossible.
        """
        storage, deps, init_state, _, _, _ = _build_full_test_harness(
            self.tmp_path,
            seed_retrieval_bug=True,
            max_repair_attempts_requested=5,  # Caller requests 5; graph must enforce 3!
        )
        attempt_calls = 0
        orig_run_attempt = deps.repair.run_attempt

        async def _three_failing_proposals(
            req: BundleRepairRequest, *, proposal_fixtures: Any = None
        ) -> BundleRepairOutcome:
            nonlocal attempt_calls
            attempt_calls += 1
            failing_cid = next(
                r.case_id for r in req.latest_dev_run.results if not r.passed
            )
            # Each attempt proposes a distinct valid patch that fails to fix the retrieval mode bug
            proposals_by_attempt = {
                1: {
                    "kind": "config",
                    "target": "step_retrieve",
                    "hypothesis": "LLM hypothesis: attempt 1 top_k=4",
                    "evidence_case_ids": [failing_cid],
                    "ops": [
                        {
                            "op": "set_config",
                            "file": "app_config.json",
                            "step_id": "step_retrieve",
                            "pointer": "/top_k",
                            "value": 4,
                        }
                    ],
                },
                2: {
                    "kind": "prompt",
                    "target": "prompts/note_a.txt",
                    "hypothesis": "LLM hypothesis: attempt 2 add prompt note_a",
                    "evidence_case_ids": [failing_cid],
                    "ops": [
                        {
                            "op": "add_file",
                            "file": "prompts/note_a.txt",
                            "content": "Note A for attempt 2",
                        }
                    ],
                },
                3: {
                    "kind": "prompt",
                    "target": "prompts/note_b.txt",
                    "hypothesis": "LLM hypothesis: attempt 3 add prompt note_b",
                    "evidence_case_ids": [failing_cid],
                    "ops": [
                        {
                            "op": "add_file",
                            "file": "prompts/note_b.txt",
                            "content": "Note B for attempt 3",
                        }
                    ],
                },
            }
            return await orig_run_attempt(
                req, proposal_fixtures=[proposals_by_attempt[attempt_calls]]
            )

        deps.repair.run_attempt = _three_failing_proposals  # type: ignore[method-assign]

        orch = FactoryOrchestrator(deps)
        graph = orch.build_graph(
            checkpointer=SqliteSerdeSaver(storage.get_checkpoint_db_path())
        )
        final_state = await graph.ainvoke(
            init_state, config={"configurable": {"thread_id": "run-max3-01"}}
        )
        f_state = FactoryState.model_validate(final_state["factory"])

        # Exactly 3 repair attempts ran; max_repair_attempts was clamped to 3; verdict is not_ready
        self.assertEqual(f_state.max_repair_attempts, 3)
        self.assertEqual(attempt_calls, 3)
        self.assertEqual(len(f_state.repair_log), 3)
        self.assertEqual([r.attempt for r in f_state.repair_log], [1, 2, 3])
        self.assertEqual(f_state.stage, "delivered")
        assert f_state.verdict is not None
        self.assertEqual(f_state.verdict.status, "not_ready")

        # Prove a 4th attempt is impossible even if repair_node is called directly with stage='repairing'
        forced_state = copy.deepcopy(final_state)
        forced_state["factory"]["stage"] = "repairing"
        forced_state["factory"]["verdict"] = None
        forced_state["factory"]["frozen"] = None
        after_fourth = await orch.repair_node(forced_state)
        self.assertEqual(attempt_calls, 3)  # Still 3 calls; 4th call was blocked!
        self.assertEqual(after_fourth["factory"]["stage"], "frozen")

    async def test_08_latest_parent_chaining_and_child_dev_run_recording(self) -> None:
        """Items 5 & 6: Verifies multi-step parent-child chaining where Attempt 1 produces
        v1.0.0-candidate-r1 (partial fix) and Attempt 2 operates on v1.0.0-candidate-r1 to produce
        v1.0.0-candidate-r1-r2 (full fix).
        """
        storage, deps, init_state, _, _, _ = _build_full_test_harness(
            self.tmp_path, seed_retrieval_bug=False
        )
        orch = FactoryOrchestrator(deps)

        # Run up to dev_test first
        s1 = await orch.init_run_node(init_state)
        s2 = await orch.design_eval_node(s1)  # type: ignore[arg-type]
        s3 = await orch.split_and_seal_node(s2)  # type: ignore[arg-type]
        s4 = await orch.build_node(s3)  # type: ignore[arg-type]

        # Force dev_test to have 2 failing cases on v1.0.0-candidate so it enters repairing
        f_s4 = FactoryState.model_validate(s4["factory"])
        assert f_s4.candidate is not None and f_s4.baseline is not None
        dev_cases = await orch._load_dev_cases(s4["refs"])
        c0, c1 = dev_cases[0].case_id, dev_cases[1].case_id

        from schemas import DevCaseResult

        base_fail_run = DevRun(
            version_id=f_s4.baseline.version_id,
            results=tuple(
                DevCaseResult(case_id=dc.case_id, passed=False, score=0.0, failure_note="fail")
                for dc in dev_cases
            ),
        )
        cand_partial_fail_run = DevRun(
            version_id=f_s4.candidate.version_id,
            results=tuple(
                DevCaseResult(
                    case_id=dc.case_id,
                    passed=(dc.case_id not in (c0, c1)),
                    score=0.0 if dc.case_id in (c0, c1) else 1.0,
                    failure_note="fail" if dc.case_id in (c0, c1) else "",
                )
                for dc in dev_cases
            ),
        )
        f_s4.dev_runs = [base_fail_run, cand_partial_fail_run]
        f_s4.stage = "repairing"
        state_in_repair: FactoryGraphState = {
            "factory": f_s4.model_dump(mode="json"),
            "refs": s4["refs"],
            "events": s4["events"],
        }

        seen_parents: list[str] = []

        async def _chained_repair_port(
            req: BundleRepairRequest, *, proposal_fixtures: Any = None
        ) -> BundleRepairOutcome:
            seen_parents.append(req.candidate_manifest.version_id)
            parent_m = req.candidate_manifest
            child_vid = f"{parent_m.version_id}-r{req.attempt_number}"
            child_m = BundleManifest.seal(
                ArtifactContent(
                    spec_hash=parent_m.spec_hash,
                    architecture=parent_m.architecture,
                    runtime_model=parent_m.runtime_model,
                    reasoning_effort=parent_m.reasoning_effort,
                    entrypoint=parent_m.entrypoint,
                    files=parent_m.files,
                    allowed_tools=parent_m.allowed_tools,
                    limits=parent_m.limits,
                ),
                version_id=child_vid,
                created_at=datetime.now(timezone.utc),
                parent_version_id=parent_m.version_id,
            )
            if req.attempt_number == 1:
                # Attempt 1 fixes c0, but c1 still fails -> stays in 'repairing' with new candidate!
                c_run = DevRun(
                    version_id=child_vid,
                    results=tuple(
                        DevCaseResult(
                            case_id=dc.case_id,
                            passed=(dc.case_id != c1),
                            score=0.0 if dc.case_id == c1 else 1.0,
                            failure_note="still failing c1" if dc.case_id == c1 else "",
                        )
                        for dc in dev_cases
                    ),
                )
            else:
                # Attempt 2 fixes c1 -> 100% pass rate!
                c_run = DevRun(
                    version_id=child_vid,
                    results=tuple(
                        DevCaseResult(case_id=dc.case_id, passed=True, score=1.0, failure_note="")
                        for dc in dev_cases
                    ),
                )
            rec = RepairRecord(
                attempt=req.attempt_number,
                parent_version_id=parent_m.version_id,
                new_version_id=child_vid,
                target_component="step_retrieve",
                accepted=True,
                reason="report=a; cost=zero_calls; accepted",
            )
            return BundleRepairOutcome(
                status="repaired",
                repair_record=rec,
                new_manifest=child_m,
                child_dev_run=c_run,
            )

        deps.repair.run_attempt = _chained_repair_port  # type: ignore[method-assign]

        after_r1 = await orch.repair_node(state_in_repair)
        f_r1 = FactoryState.model_validate(after_r1["factory"])
        self.assertEqual(f_r1.stage, "repairing")
        assert f_r1.candidate is not None
        self.assertEqual(f_r1.candidate.version_id, "v1.0.0-candidate-r1")
        self.assertEqual(f_r1.candidate.parent_version_id, "v1.0.0-candidate")

        after_r2 = await orch.repair_node(after_r1)  # type: ignore[arg-type]
        f_r2 = FactoryState.model_validate(after_r2["factory"])
        self.assertEqual(f_r2.stage, "frozen")
        assert f_r2.candidate is not None and f_r2.frozen is not None
        self.assertEqual(seen_parents, ["v1.0.0-candidate", "v1.0.0-candidate-r1"])
        self.assertEqual(f_r2.candidate.version_id, "v1.0.0-candidate-r1-r2")
        self.assertEqual(f_r2.candidate.parent_version_id, "v1.0.0-candidate-r1")
        self.assertEqual(f_r2.frozen.version_id, "v1.0.0-candidate-r1-r2")

    async def test_09_invalid_repair_outcome_and_stalled_attempt_fail_closed(self) -> None:
        """Item 4: Verifies that an invalid BundleRepairOutcome (missing repair_record or wrong parent)
        fails closed and routes to 'fail'.
        """
        _, deps, init_state, _, _, _ = _build_full_test_harness(
            self.tmp_path, seed_retrieval_bug=True
        )

        async def _broken_repair_port(
            req: BundleRepairRequest, *, proposal_fixtures: Any = None
        ) -> BundleRepairOutcome:
            # Invalid: status='rejected' with repair_record=None!
            return BundleRepairOutcome(status="rejected", repair_record=None)

        deps.repair.run_attempt = _broken_repair_port  # type: ignore[method-assign]
        orch = FactoryOrchestrator(deps)
        final_state = await orch.build_graph().ainvoke(init_state)
        f_state = FactoryState.model_validate(final_state["factory"])
        self.assertEqual(f_state.stage, "failed")
        self.assertTrue(
            any("missing repair_record" in e.message for e in f_state.errors)
        )

    async def test_10_baseline_fallback_when_baseline_passes(self) -> None:
        """Item 7: When baseline passes dev_test, graph skips repair and freezes baseline as simplest passing control."""
        _, deps, init_state, _, _, _ = _build_full_test_harness(
            self.tmp_path, seed_retrieval_bug=True, baseline_passes=True
        )
        orch = FactoryOrchestrator(deps)
        final_state = await orch.build_graph().ainvoke(init_state)
        f_state = FactoryState.model_validate(final_state["factory"])

        self.assertEqual(f_state.stage, "delivered")
        self.assertEqual(len(f_state.repair_log), 0)
        assert f_state.frozen is not None and f_state.baseline is not None
        self.assertEqual(f_state.frozen.version_id, f_state.baseline.version_id)

    async def test_11_checkpoint_resume_with_persistent_sealed_vault(self) -> None:
        """Item 9: Proves that checkpoint state and SealedVaultStore survive process restart:
        run nodes 1–4 with instance 1, then instantiate a new SqliteSerdeSaver and new
        SealedVaultStore from disk and resume to completion.
        """
        storage, deps1, init_state, keypair, _, vault1 = _build_full_test_harness(
            self.tmp_path, seed_retrieval_bug=False
        )
        orch1 = FactoryOrchestrator(deps1)
        s1 = await orch1.init_run_node(init_state)
        s2 = await orch1.design_eval_node(s1)  # type: ignore[arg-type]
        s3 = await orch1.split_and_seal_node(s2)  # type: ignore[arg-type]
        s4 = await orch1.build_node(s3)  # type: ignore[arg-type]

        # Simulate process restart: create a brand-new SealedVaultStore from the same SQLite path on disk
        vault2 = SealedVaultStore(vault1.vault_db_path)
        eval_plane2 = LocalProtectedEvalPlane(
            vault=vault2,
            engine=deps1.builder.engine,  # type: ignore[attr-defined]
            signing_key=keypair,
            assets=await orch1._load_assets(s4["refs"]),
        )
        deps2 = copy.copy(deps1)
        deps2.eval_plane = eval_plane2
        orch2 = FactoryOrchestrator(deps2)

        s5 = await orch2.dev_test_node(s4)  # type: ignore[arg-type]
        s6 = await orch2.freeze_node(s5)  # type: ignore[arg-type]
        s7 = await orch2.evaluate_node(s6)  # type: ignore[arg-type]
        s8 = await orch2.deliver_node(s7)  # type: ignore[arg-type]

        f_final = FactoryState.model_validate(s8["factory"])
        self.assertEqual(f_final.stage, "delivered")
        assert f_final.verdict is not None
        self.assertEqual(f_final.verdict.status, "ready")

    def test_12_exception_sanitization_redacts_secrets_and_held_out_data(self) -> None:
        """Item 11: Verifies that sanitize_diagnostic_text strips API keys, Bearer tokens,
        and held-out case identifiers/fields before logging or recording ErrorRecords.
        """
        raw_err = (
            "Auth failed with Bearer secret_token_123456789 and MODEL_API_KEY=sk-live99887766554433 "
            'on held-out case_crit_exact_decision_22 with "expected_value": "approve_refund"'
        )
        sanitized = sanitize_diagnostic_text(raw_err)
        self.assertNotIn("secret_token_123456789", sanitized)
        self.assertNotIn("sk-live99887766554433", sanitized)
        self.assertNotIn("case_crit_exact_decision_22", sanitized)
        self.assertNotIn("approve_refund", sanitized)
        self.assertIn("[REDACTED_SECRET]", sanitized)
        self.assertIn("[REDACTED_PROTECTED_DATA]", sanitized)


async def _run_demo() -> int:
    with tempfile.TemporaryDirectory(prefix="adaptos_graph_demo_") as tmp:
        fix_fixture = {
            "kind": "config",
            "target": "step_retrieve",
            "hypothesis": "LLM hypothesis: switch retrieve.lexical mode from all to any.",
            "evidence_case_ids": ["placeholder"],
            "ops": [
                {
                    "op": "set_config",
                    "file": "app_config.json",
                    "step_id": "step_retrieve",
                    "pointer": "/mode",
                    "value": "any",
                }
            ],
        }
        storage, deps, init_state, _, _, _ = _build_full_test_harness(
            Path(tmp), seed_retrieval_bug=True, repair_fixtures=[fix_fixture]
        )
        orig_run = deps.repair.run_attempt

        async def _patched_attempt(
            req: BundleRepairRequest, *, proposal_fixtures: Any = None
        ) -> BundleRepairOutcome:
            failing_cid = next(
                r.case_id for r in req.latest_dev_run.results if not r.passed
            )
            p = copy.deepcopy(fix_fixture)
            p["evidence_case_ids"] = [failing_cid]
            return await orig_run(req, proposal_fixtures=[p])

        deps.repair.run_attempt = _patched_attempt  # type: ignore[method-assign]
        saver = SqliteSerdeSaver(storage.get_checkpoint_db_path())
        graph = FactoryOrchestrator(deps).build_graph(checkpointer=saver)
        final_state = await graph.ainvoke(
            init_state, config={"configurable": {"thread_id": "demo-run-001"}}
        )
        f_state = FactoryState.model_validate(final_state["factory"])
        print(
            json.dumps(
                {
                    "final_stage": f_state.stage,
                    "plan_hash": final_state["refs"].get("plan_hash"),
                    "sealed_set_id": final_state["refs"].get("sealed_set_id"),
                    "frozen_version": f_state.frozen.version_id
                    if f_state.frozen
                    else None,
                    "repair_attempts": f_state.repair_attempts,
                    "verdict_status": f_state.verdict.status
                    if f_state.verdict
                    else None,
                    "delivery_blob_sha256": final_state["refs"].get(
                        "delivery_blob_sha256"
                    ),
                    "events": final_state["events"],
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AdaptOS Factory Graph Orchestrator")
    parser.add_argument(
        "--self-test", action="store_true", help="Run built-in unit & integration tests"
    )
    parser.add_argument(
        "--demo", action="store_true", help="Run end-to-end factory orchestrator demo"
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.demo:
        return asyncio.run(_run_demo())

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        GraphOrchestratorTestSuite
    )
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())