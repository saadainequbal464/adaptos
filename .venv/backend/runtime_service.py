"""backend/runtime_service.py — AdaptOS Generic MVP Runtime Backend.

Responsibilities:
1. ApplicationPackageManager: Validates Factory-generated ZIP archives, defends against
   ZIP bombs, symlink attacks, and path traversal, verifies Ed25519 Verdict signatures and
   `status == 'ready'`, verifies `spec_hash` and `artifact_hash` chains, and runs
   `AppRuntime.verify_bundle_integrity()`.
2. RuntimeProvisioner & ApplicationRuntimeManager: Provisions isolated version-scoped
   per-application storage without destructively wiping existing data or conversations,
   validates generated tool components via `SandboxVerifier` (failing closed if Docker is
   unavailable for `tool_use` bundles), enforces the 7-state lifecycle
   (VERIFIED -> PROVISIONING -> READY -> ACTIVE <-> STOPPED -> DEACTIVATED / FAILED),
   and safely recovers applications interrupted in `PROVISIONING` after a crash.
3. MuseApiClient: Backend-only Muse API integration implementing `RuntimeModelPort` with
   environment-sourced credentials (`MODEL_API_KEY` / `MUSE_API_KEY`, `META_BASE_URL` /
   `MUSE_API_BASE_URL`), `max_completion_tokens`, `response_format={"type": "json_schema",
   "json_schema": {"name": ..., "schema": ...}}`, request timeouts, and error classification.
4. ConversationSessionManager: Persists multi-turn sessions and messages in SQLite,
   retrieves the latest N messages in chronological order, and enforces `(app_id, owner_id,
   session_id)` isolation (defaulting to server-controlled single-owner `default_owner`).
5. ChatExecutionPipeline & AdaptOSRuntimeService: Deterministically maps unambiguous inputs
   (returning a structured `clarification_required` response when required inputs are missing
   or invalid), executes the bundle's `PlanStep` workflow via `AppRuntime.execute_bundle()`,
   returns only genuinely verified citations with original asset provenance, and persists turns.

MVP Architectural Scope Note:
This Runtime Backend executes the AdaptOS Factory's manifest-driven `PlanStep` application
bundles (`prompt_only`, `retrieval`, `tool_use` with sandboxed `fn.<id>` components). It does
not execute arbitrary standalone FastAPI servers or unverified Python packages.
"""
from __future__ import annotations

import argparse
import hashlib
import asyncio
import io
import json
import os
import re
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Final, Literal, Mapping, Protocol, Sequence

# Package-compatible imports supporting both `backend.runtime_service` and `runtime_service`
if __package__:
    from .schemas import (
        AcceptanceCriterion,
        ArtifactContent,
        ArtifactFile,
        BundleManifest,
        CriterionResult,
        DeliveryPackage,
        FieldSpec,
        Identifier,
        RuntimeLimits,
        Sha256Hex,
        Spec,
        Verdict,
        canonical_json,
        sha256_hex,
    )
    from .storage import StorageConfig, StorageService
    from .sandbox import (
        SandboxConfig,
        SandboxVerifier,
        _simulated_docker_runner_for_tests,
    )
    from .runtime import (
        AppRuntime,
        PlanStep,
        RuntimeExecutionError,
        SourceAssetInput,
        StepTrace,
    )
    from eval_plane.evaluator import Ed25519Signer
else:
    _CURRENT_DIR = Path(__file__).resolve().parent
    _PARENT_DIR = _CURRENT_DIR.parent
    _EVAL_DIR = _CURRENT_DIR / "eval_plane"
    for _p in (_EVAL_DIR, _CURRENT_DIR, _PARENT_DIR):
        if _p.is_dir() and str(_p) not in os.sys.path:
            os.sys.path.insert(0, str(_p))

    from schemas import (  # type: ignore[no-redef]
        AcceptanceCriterion,
        ArtifactContent,
        ArtifactFile,
        BundleManifest,
        CriterionResult,
        DeliveryPackage,
        FieldSpec,
        Identifier,
        RuntimeLimits,
        Sha256Hex,
        Spec,
        Verdict,
        canonical_json,
        sha256_hex,
    )
    from storage import StorageConfig, StorageService  # type: ignore[no-redef]
    from sandbox import (  # type: ignore[no-redef]
        SandboxConfig,
        SandboxVerifier,
        _simulated_docker_runner_for_tests,
    )
    from runtime import (  # type: ignore[no-redef]
        AppRuntime,
        PlanStep,
        RuntimeExecutionError,
        SourceAssetInput,
        StepTrace,
    )
    try:
        from eval_plane.evaluator import Ed25519Signer  # type: ignore[no-redef]
    except ImportError:
        from evaluator import Ed25519Signer  # type: ignore[no-redef]

from pydantic import BaseModel, ConfigDict, Field


def _canonical_bytes(data: Any) -> bytes:
    res = canonical_json(data)
    return res if isinstance(res, bytes) else str(res).encode("utf-8")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


# =========================================================================== #
# 1. EXCEPTIONS, IDENTIFIER VALIDATION, LIFECYCLE ENUM & CONFIGURATION
# =========================================================================== #

DEFAULT_RUNTIME_OWNER_ID: Final[str] = "default_owner"
_SAFE_IDENTIFIER_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$"
)


class RuntimeServiceError(RuntimeError):
    """Base exception for all Runtime Backend errors (never leaks internal paths or secrets)."""

    def __init__(self, message: str, *, code: str = "runtime_service_error") -> None:
        super().__init__(message)
        self.code = code


class InvalidIdentifierError(RuntimeServiceError):
    """Raised when an app_id, project_run_id, session_id, or owner_id is malformed or unsafe."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="invalid_identifier")


class PackageValidationError(RuntimeServiceError):
    """Raised when a ZIP package fails security, structure, hash, or Verdict checks."""

    def __init__(self, message: str, *, code: str = "package_validation_failed") -> None:
        super().__init__(message, code=code)


class ProvisioningError(RuntimeServiceError):
    """Raised when application provisioning or sandbox verification fails."""

    def __init__(self, message: str, *, code: str = "provisioning_failed") -> None:
        super().__init__(message, code=code)


class LifecycleStateError(RuntimeServiceError):
    """Raised when an operation is invalid for the application's current lifecycle state."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="invalid_lifecycle_state")


class RuntimeAuthorizationError(RuntimeServiceError):
    """Raised when an owner/project boundary check fails."""

    def __init__(self, message: str = "Access denied to application or session.") -> None:
        super().__init__(message, code="runtime_authorization_failed")


class UnsupportedArchitectureError(RuntimeServiceError):
    """Raised when a bundle uses an architecture or component not supported by the runtime."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="unsupported_architecture")


class MuseProviderError(RuntimeServiceError):
    """Raised when the Muse API call fails, times out, or returns an invalid payload."""

    def __init__(self, message: str, *, code: str = "muse_provider_error") -> None:
        super().__init__(message, code=code)


class MuseAuthenticationError(MuseProviderError):
    """Raised when Muse API credentials are missing or rejected (HTTP 401/403)."""

    def __init__(self, message: str = "Muse API authentication failed.") -> None:
        super().__init__(message, code="muse_auth_failed")


class MuseRateLimitError(MuseProviderError):
    """Raised when Muse API rate limits are exceeded (HTTP 429)."""

    def __init__(self, message: str = "Muse API rate limit exceeded.") -> None:
        super().__init__(message, code="muse_rate_limited")


class MuseProviderTimeoutError(MuseProviderError):
    """Raised when a Muse API request exceeds the configured timeout."""

    def __init__(self, message: str = "Muse API request timed out.") -> None:
        super().__init__(message, code="muse_timeout")


def validate_safe_identifier(value: str, *, field_name: str) -> str:
    """Validates an identifier against path traversal and injection characters."""
    if not isinstance(value, str):
        raise InvalidIdentifierError(f"{field_name} must be a string.")
    cleaned = value.strip()
    if (
        not cleaned
        or ".." in cleaned
        or "/" in cleaned
        or "\\" in cleaned
        or "\x00" in cleaned
        or not _SAFE_IDENTIFIER_RE.match(cleaned)
    ):
        raise InvalidIdentifierError(
            f"Invalid {field_name} '{value}': must match ^[A-Za-z0-9][A-Za-z0-9_.\\-]{{0,63}}$ with no path separators or '..'."
        )
    return cleaned


def _resolve_contained_path(base_root: Path, *relative_parts: str) -> Path:
    """Resolves a path under `base_root` and verifies it cannot escape `base_root`."""
    resolved_root = base_root.resolve()
    safe_parts = [
        validate_safe_identifier(part, field_name="path_segment")
        for part in relative_parts
    ]
    candidate = resolved_root.joinpath(*safe_parts).resolve()
    try:
        is_inside = candidate.is_relative_to(resolved_root)
    except AttributeError:
        is_inside = resolved_root == candidate or resolved_root in candidate.parents
    if not is_inside or candidate == resolved_root:
        raise InvalidIdentifierError(
            "Resolved path escaped the designated runtime storage root."
        )
    return candidate


class RuntimeLifecycleState(str, Enum):
    """Generic application lifecycle states managed by ApplicationRuntimeManager."""

    VERIFIED = "VERIFIED"
    PROVISIONING = "PROVISIONING"
    READY = "READY"
    ACTIVE = "ACTIVE"
    STOPPED = "STOPPED"
    FAILED = "FAILED"
    DEACTIVATED = "DEACTIVATED"


SUPPORTED_ARCHITECTURES: Final[frozenset[str]] = frozenset(
    {"prompt_only", "retrieval", "tool_use"}
)

SUPPORTED_RUNTIME_COMPONENTS: Final[frozenset[str]] = frozenset(
    {
        "workflow.linear",
        "io.validate",
        "doc.ingest",
        "retrieve.lexical",
        "fn.sandboxed",
        "prompt.compose",
        "model.chat",
        "output.structured",
        "cite.verify",
        "log.trace",
    }
)


@dataclass(frozen=True)
class RuntimeServiceConfig:
    """Configuration for `AdaptOSRuntimeService`.

    Single-Owner MVP Isolation Note:
    When `enforce_single_owner_mode=True` (default), all operations are bound to the
    server-controlled `default_owner_id` (`"default_owner"`), and any attempt to access
    resources under a different owner ID is rejected.
    """

    runtime_data_root: Path
    eval_public_key_bytes: bytes
    muse_api_base_url: str = field(
        default_factory=lambda: os.environ.get(
            "META_BASE_URL",
            os.environ.get("MUSE_API_BASE_URL", "https://api.meta.ai/v1"),
        )
    )
    muse_api_key: str = field(
        default_factory=lambda: os.environ.get(
            "MODEL_API_KEY", os.environ.get("MUSE_API_KEY", "")
        )
    )
    muse_request_timeout_seconds: float = 25.0
    max_zip_bytes: int = 10_000_000
    max_uncompressed_bytes: int = 25_000_000
    max_archive_files: int = 64
    max_compression_ratio: float = 50.0
    max_history_turns_in_prompt: int = 10
    default_owner_id: str = DEFAULT_RUNTIME_OWNER_ID
    enforce_single_owner_mode: bool = False
    allow_subprocess_sandbox_fallback: bool = False


# =========================================================================== #
# 2. PUBLIC DATA MODELS (Pydantic Contracts)
# =========================================================================== #


class StrictRuntimeServiceModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FrozenRuntimeServiceModel(StrictRuntimeServiceModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ApplicationSpecificConfig(FrozenRuntimeServiceModel):
    """Application-specific configuration extracted from a verified artifact package."""

    app_id: Identifier
    project_run_id: str
    version_id: Identifier
    artifact_hash: Sha256Hex
    spec_hash: Sha256Hex
    architecture: Literal["prompt_only", "retrieval", "tool_use"]
    goal: str
    system_instructions: str
    verbatim_constraints: tuple[str, ...]
    acceptance_criteria: tuple[AcceptanceCriterion, ...]
    spec_inputs: tuple[FieldSpec, ...]
    spec_outputs: tuple[FieldSpec, ...]
    input_json_schema: dict[str, Any]
    output_json_schema: dict[str, Any]
    runtime_model: str
    reasoning_effort: Literal["low", "medium", "high"]
    steps: tuple[PlanStep, ...]
    allowed_tools: tuple[str, ...]
    limits: RuntimeLimits
    uses_retrieval: bool
    uses_sandboxed_tools: bool
    retrieval_step_config: dict[str, Any] = Field(default_factory=dict)
    ingest_step_config: dict[str, Any] = Field(default_factory=dict)
    citation_field: str | None = None
    citation_match_mode: str = "substring"
    citation_require_non_empty: bool = True


class RuntimeApplicationSummary(FrozenRuntimeServiceModel):
    """Public status of a provisioned application in the Runtime Backend."""

    app_id: Identifier
    project_run_id: str
    owner_id: str
    version_id: Identifier
    artifact_hash: Sha256Hex
    spec_hash: Sha256Hex
    verdict_id: str
    verdict_status: Literal["ready"]
    architecture: Literal["prompt_only", "retrieval", "tool_use"]
    runtime_model: str
    goal: str
    state: RuntimeLifecycleState
    uses_retrieval: bool
    uses_sandboxed_tools: bool
    ingested_asset_count: int = 0
    error_code: str | None = None
    error_message: str | None = None
    provisioned_at: datetime
    updated_at: datetime


class SourceReference(FrozenRuntimeServiceModel):
    """Genuine retrieval or citation reference with original asset provenance."""

    doc_id: str
    asset_id: str | None = None
    filename: str | None = None
    excerpt: str
    score: float = 0.0
    citation_verified: bool = False
    verified_citation: str | None = None


class ConversationMessage(FrozenRuntimeServiceModel):
    """Persisted message within an application conversation session."""

    message_id: str
    session_id: str
    app_id: str
    role: Literal["user", "assistant"]
    content: str
    structured_payload: dict[str, Any] = Field(default_factory=dict)
    source_references: tuple[SourceReference, ...] = ()
    step_traces: tuple[StepTrace, ...] = ()
    created_at: datetime


class ConversationSessionSummary(FrozenRuntimeServiceModel):
    """Summary metadata for a user's conversation session with an adapted application."""

    session_id: str
    app_id: str
    owner_id: str
    title: str
    message_count: int = 0
    created_at: datetime
    updated_at: datetime


class ChatTurnResponse(FrozenRuntimeServiceModel):
    """Result returned by `send_chat_message()` after executing the application workflow
    or requesting structured input clarification.
    """

    app_id: str
    session_id: str
    status: Literal["completed", "clarification_required"] = "completed"
    user_message: ConversationMessage
    assistant_message: ConversationMessage
    structured_output: dict[str, Any]
    missing_fields: tuple[str, ...] = ()
    validation_errors: tuple[str, ...] = ()
    source_references: tuple[SourceReference, ...] = ()
    wall_time_ms: int


# =========================================================================== #
# 3. A. APPLICATION PACKAGE MANAGER (Safe ZIP Extraction & Verification)
# =========================================================================== #


@dataclass(frozen=True)
class VerifiedPackageContents:
    delivery_package: DeliveryPackage
    bundle_files: dict[str, bytes]
    bundled_assets: tuple[SourceAssetInput, ...]
    app_config: ApplicationSpecificConfig


class ApplicationPackageManager:
    """Validates Factory-generated ZIP archives, defends against ZIP bombs and path traversal,
    verifies Ed25519 Verdict authenticity and `status == 'ready'`, and verifies file hashes.
    """

    _WIN_DRIVE_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z]:")

    def __init__(self, config: RuntimeServiceConfig) -> None:
        self.config = config

    @classmethod
    def _validate_safe_zip_member_path(cls, raw_name: str) -> str:
        if not raw_name or "\x00" in raw_name:
            raise PackageValidationError(
                "Archive contains an empty or null-byte filename.",
                code="unsafe_archive_path",
            )
        if (
            "\\" in raw_name
            or raw_name.startswith("/")
            or cls._WIN_DRIVE_RE.match(raw_name)
        ):
            raise PackageValidationError(
                f"Archive member '{raw_name}' uses an absolute, backslash, or drive-letter path.",
                code="unsafe_archive_path",
            )
        norm = Path(raw_name).as_posix()
        parts = norm.split("/")
        if any(p in ("", ".", "..") for p in parts):
            raise PackageValidationError(
                f"Archive member '{raw_name}' contains path traversal segments.",
                code="unsafe_archive_path",
            )
        return norm

    def extract_and_verify_zip(
        self,
        zip_payload: bytes | Path | io.BytesIO,
        *,
        project_run_id: str,
        app_id: str,
        external_assets: Sequence[SourceAssetInput] = (),
    ) -> VerifiedPackageContents:
        safe_run_id = validate_safe_identifier(
            project_run_id, field_name="project_run_id"
        )
        safe_app_id = validate_safe_identifier(app_id, field_name="app_id")

        if isinstance(zip_payload, Path):
            if not zip_payload.is_file():
                raise PackageValidationError("ZIP archive file does not exist.")
            if zip_payload.stat().st_size > self.config.max_zip_bytes:
                raise PackageValidationError(
                    "ZIP archive exceeds max_zip_bytes limit.",
                    code="archive_too_large",
                )
            raw_zip_bytes = zip_payload.read_bytes()
        elif isinstance(zip_payload, io.BytesIO):
            raw_zip_bytes = zip_payload.getvalue()
        elif isinstance(zip_payload, (bytes, bytearray)):
            raw_zip_bytes = bytes(zip_payload)
        else:
            raise PackageValidationError("Unsupported zip_payload type.")

        if not raw_zip_bytes:
            raise PackageValidationError("ZIP archive is empty.")
        if len(raw_zip_bytes) > self.config.max_zip_bytes:
            raise PackageValidationError(
                f"ZIP archive size ({len(raw_zip_bytes)} bytes) exceeds max_zip_bytes ({self.config.max_zip_bytes}).",
                code="archive_too_large",
            )

        try:
            zf = zipfile.ZipFile(io.BytesIO(raw_zip_bytes), mode="r")
        except Exception as exc:
            raise PackageValidationError(
                f"Corrupted or invalid ZIP archive: {type(exc).__name__}.",
                code="corrupted_archive",
            ) from exc

        extracted_files: dict[str, bytes] = {}
        total_uncompressed = 0
        total_compressed = 0

        with zf:
            infos = zf.infolist()
            if not infos:
                raise PackageValidationError("ZIP archive contains zero entries.")
            if len(infos) > self.config.max_archive_files:
                raise PackageValidationError(
                    f"ZIP archive contains {len(infos)} entries, exceeding limit ({self.config.max_archive_files}).",
                    code="too_many_archive_files",
                )

            for info in infos:
                if info.is_dir():
                    raise PackageValidationError(
                        "ZIP archive must not contain explicit directory entries.",
                        code="unsafe_archive_entry",
                    )
                unix_mode = (info.external_attr >> 16) & 0o170000
                if unix_mode == 0o120000:
                    raise PackageValidationError(
                        f"Archive member '{info.filename}' is a symbolic link.",
                        code="unsafe_symlink_entry",
                    )

                safe_path = self._validate_safe_zip_member_path(info.filename)
                if safe_path in extracted_files:
                    raise PackageValidationError(
                        f"Duplicate archive entry '{safe_path}'.",
                        code="duplicate_archive_entry",
                    )

                if info.file_size > self.config.max_uncompressed_bytes:
                    raise PackageValidationError(
                        f"Archive member '{safe_path}' declared size exceeds uncompressed limit.",
                        code="zip_bomb_detected",
                    )
                compressed_sz = max(1, info.compress_size)
                if (
                    info.file_size > 1024
                    and (info.file_size / compressed_sz) > self.config.max_compression_ratio
                ):
                    raise PackageValidationError(
                        f"Archive member '{safe_path}' exceeds maximum compression ratio ({self.config.max_compression_ratio}:1).",
                        code="zip_bomb_detected",
                    )

                remaining_budget = (
                    self.config.max_uncompressed_bytes - total_uncompressed
                )
                with zf.open(info, mode="r") as member_fp:
                    data = member_fp.read(remaining_budget + 1)
                if len(data) > remaining_budget:
                    raise PackageValidationError(
                        "Total uncompressed archive bytes exceeded max_uncompressed_bytes limit.",
                        code="zip_bomb_detected",
                    )
                if len(data) != info.file_size:
                    raise PackageValidationError(
                        f"Archive member '{safe_path}' actual byte length ({len(data)}) != ZIP header file_size ({info.file_size}).",
                        code="corrupted_archive",
                    )

                total_uncompressed += len(data)
                total_compressed += compressed_sz
                extracted_files[safe_path] = data

            if (
                total_uncompressed > 2048
                and (total_uncompressed / max(1, total_compressed))
                > self.config.max_compression_ratio
            ):
                raise PackageValidationError(
                    "Total archive compression ratio exceeds maximum allowed limit.",
                    code="zip_bomb_detected",
                )

        if "delivery_package.json" not in extracted_files:
            raise PackageValidationError(
                "Missing required 'delivery_package.json' in ZIP archive.",
                code="missing_delivery_package",
            )

        try:
            pkg_dict = json.loads(
                extracted_files.pop("delivery_package.json").decode("utf-8")
            )
            delivery_pkg = DeliveryPackage.model_validate(pkg_dict)
        except Exception as exc:
            raise PackageValidationError(
                f"Invalid 'delivery_package.json': {exc}",
                code="invalid_delivery_package",
            ) from exc

        bundled_assets: list[SourceAssetInput] = list(external_assets)
        if (
            "assets/source_assets.json" in extracted_files
            and not any(
                af.path == "assets/source_assets.json"
                for af in delivery_pkg.manifest.files
            )
        ):
            try:
                raw_assets = json.loads(
                    extracted_files.pop("assets/source_assets.json").decode(
                        "utf-8"
                    )
                )
                for item in raw_assets:
                    bundled_assets.append(SourceAssetInput.model_validate(item))
            except Exception as exc:
                raise PackageValidationError(
                    f"Malformed 'assets/source_assets.json': {exc}",
                    code="invalid_bundled_assets",
                ) from exc

        return self.verify_delivery_package_and_files(
            delivery_package=delivery_pkg,
            bundle_files=extracted_files,
            project_run_id=safe_run_id,
            app_id=safe_app_id,
            assets=bundled_assets,
        )

    def verify_delivery_package_and_files(
        self,
        *,
        delivery_package: DeliveryPackage,
        bundle_files: Mapping[str, bytes],
        project_run_id: str,
        app_id: str,
        assets: Sequence[SourceAssetInput] = (),
    ) -> VerifiedPackageContents:
        safe_run_id = validate_safe_identifier(
            project_run_id, field_name="project_run_id"
        )
        safe_app_id = validate_safe_identifier(app_id, field_name="app_id")

        spec = delivery_package.spec
        manifest = delivery_package.manifest
        verdict = delivery_package.verdict

        # 1. Verify Ed25519 Verdict signature using Protected Evaluation Plane public key
        if not Ed25519Signer.verify_signature(
            self.config.eval_public_key_bytes,
            verdict.signing_payload(),
            verdict.signature,
        ):
            raise PackageValidationError(
                "Verdict Ed25519 signature verification failed.",
                code="verdict_signature_invalid",
            )

        # 2. Enforce Verdict status == 'ready'
        if verdict.status != "ready":
            raise PackageValidationError(
                f"Package Verdict status is '{verdict.status}'; only 'ready' packages can be provisioned.",
                code="verdict_not_ready",
            )

        # 3. Verify cryptographic hash bindings across Spec, BundleManifest, and Verdict
        computed_spec_hash = spec.content_hash()
        if (
            verdict.spec_hash != computed_spec_hash
            or manifest.spec_hash != computed_spec_hash
        ):
            raise PackageValidationError(
                "Spec content_hash mismatch across DeliveryPackage.spec, BundleManifest, or Verdict.",
                code="spec_hash_mismatch",
            )
        if verdict.artifact != manifest.ref:
            raise PackageValidationError(
                "Verdict ArtifactRef does not match BundleManifest.ref.",
                code="artifact_ref_mismatch",
            )

        # 4. Verify supported architecture
        if manifest.architecture not in SUPPORTED_ARCHITECTURES:
            raise UnsupportedArchitectureError(
                f"Bundle architecture '{manifest.architecture}' is not supported by the MVP Runtime."
            )

        # 5. Verify bundle file integrity (every declared file exists, exact size_bytes & sha256, zero unexpected files)
        try:
            AppRuntime.verify_bundle_integrity(manifest, bundle_files)
        except Exception as exc:
            raise PackageValidationError(
                f"Bundle artifact integrity verification failed: {exc}",
                code="bundle_integrity_failed",
            ) from exc

        # 6. Parse and validate application-specific configuration
        try:
            app_cfg_raw = json.loads(
                bundle_files[manifest.entrypoint].decode("utf-8")
            )
            io_schema_raw = json.loads(
                bundle_files["schemas/io_schema.json"].decode("utf-8")
            )
            sys_prompt_text = bundle_files["prompts/system_prompt.txt"].decode(
                "utf-8"
            )
            steps = tuple(
                PlanStep.model_validate(s) for s in app_cfg_raw.get("steps", [])
            )
        except Exception as exc:
            raise PackageValidationError(
                f"Malformed bundle configuration files: {exc}",
                code="malformed_bundle_config",
            ) from exc

        if not steps:
            raise PackageValidationError(
                "Bundle 'app_config.json' contains zero execution steps.",
                code="empty_bundle_steps",
            )

        try:
            AppRuntime.validate_dependency_graph(steps)
        except Exception as exc:
            raise PackageValidationError(
                f"Invalid step dependency graph: {exc}",
                code="invalid_step_graph",
            ) from exc

        uses_retrieval = False
        uses_tools = False
        ret_cfg: dict[str, Any] = {}
        ing_cfg: dict[str, Any] = {}
        cite_field: str | None = None
        cite_match_mode = "substring"
        cite_req_non_empty = True

        for st in steps:
            cid = st.component_ref.split("@", 1)[0]
            if cid not in SUPPORTED_RUNTIME_COMPONENTS:
                raise UnsupportedArchitectureError(
                    f"Step '{st.step_id}' uses unsupported component '{cid}'."
                )
            if cid in ("doc.ingest", "retrieve.lexical"):
                uses_retrieval = True
                step_app_id = str(st.config.get("app_id", "")).strip()
                validate_safe_identifier(step_app_id, field_name="step.config.app_id")
                if cid == "retrieve.lexical":
                    ret_cfg = dict(st.config)
                else:
                    ing_cfg = dict(st.config)
            elif cid == "fn.sandboxed":
                uses_tools = True
                target_ref = str(st.config.get("target_component_ref", ""))
                if "@" not in target_ref:
                    raise PackageValidationError(
                        f"Invalid target_component_ref '{target_ref}' in step '{st.step_id}'."
                    )
                t_id, t_ver = target_ref.split("@", 1)
                if t_id not in manifest.allowed_tools:
                    raise PackageValidationError(
                        f"Sandboxed component '{t_id}' is not authorized in manifest.allowed_tools."
                    )
                fn_rel_path = f"generated/{t_id}/{t_ver}/fn.py"
                if fn_rel_path not in bundle_files:
                    raise PackageValidationError(
                        f"Missing generated function file '{fn_rel_path}'."
                    )
            elif cid == "cite.verify":
                cite_field = str(
                    st.config.get("citation_field", "policy_citation")
                )
                cite_match_mode = str(st.config.get("match_mode", "substring"))
                cite_req_non_empty = bool(
                    st.config.get("require_non_empty_retrieval", True)
                )

        app_specific_cfg = ApplicationSpecificConfig(
            app_id=safe_app_id,
            project_run_id=safe_run_id,
            version_id=manifest.version_id,
            artifact_hash=manifest.artifact_hash,
            spec_hash=manifest.spec_hash,
            architecture=manifest.architecture,
            goal=spec.goal,
            system_instructions=sys_prompt_text,
            verbatim_constraints=tuple(spec.constraints),
            acceptance_criteria=tuple(spec.acceptance_criteria),
            spec_inputs=tuple(spec.inputs),
            spec_outputs=tuple(spec.outputs),
            input_json_schema=dict(io_schema_raw.get("inputs", {})),
            output_json_schema=dict(io_schema_raw.get("outputs", {})),
            runtime_model=manifest.runtime_model,
            reasoning_effort=manifest.reasoning_effort or "low",
            steps=steps,
            allowed_tools=tuple(manifest.allowed_tools),
            limits=manifest.limits,
            uses_retrieval=uses_retrieval,
            uses_sandboxed_tools=uses_tools,
            retrieval_step_config=ret_cfg,
            ingest_step_config=ing_cfg,
            citation_field=cite_field,
            citation_match_mode=cite_match_mode,
            citation_require_non_empty=cite_req_non_empty,
        )

        return VerifiedPackageContents(
            delivery_package=delivery_package,
            bundle_files={k: bytes(v) for k, v in bundle_files.items()},
            bundled_assets=tuple(assets),
            app_config=app_specific_cfg,
        )


# =========================================================================== #
# 4. D. MUSE API CLIENT (Backend-Only Model Integration Layer)
# =========================================================================== #


class MuseProviderTransportPort(Protocol):
    """Isolated transport protocol for Muse API chat completions."""

    def create_chat_completion(
        self,
        *,
        base_url: str,
        api_key: str,
        payload: dict[str, Any],
        timeout_seconds: float,
    ) -> dict[str, Any]: ...


class OpenAICompatibleMuseHttpTransport:
    """Default HTTP transport for Meta/Muse API (`POST {base_url}/chat/completions`).

    Uses backend-held `MODEL_API_KEY` (or `MUSE_API_KEY`) and `META_BASE_URL` (or `MUSE_API_BASE_URL`).
    Never exposes credentials to the browser.
    """

    def create_chat_completion(
        self,
        *,
        base_url: str,
        api_key: str,
        payload: dict[str, Any],
        timeout_seconds: float,
    ) -> dict[str, Any]:
        if not api_key or not api_key.strip():
            raise MuseAuthenticationError(
                "Muse API key (MODEL_API_KEY / MUSE_API_KEY) is not configured in backend environment."
            )
        endpoint = f"{base_url.rstrip('/')}/chat/completions"
        body_bytes = _canonical_bytes(payload)
        req = urllib.request.Request(
            endpoint,
            data=body_bytes,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {api_key.strip()}",
            },
        )
        try:
            with urllib.request.urlopen(
                req, timeout=max(1.0, float(timeout_seconds))
            ) as resp:
                raw_resp = resp.read().decode("utf-8")
                return json.loads(raw_resp)
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise MuseAuthenticationError(
                    f"Muse API rejected credentials (HTTP {exc.code})."
                ) from exc
            if exc.code == 429:
                raise MuseRateLimitError(
                    "Muse API rate limit exceeded (HTTP 429)."
                ) from exc
            raise MuseProviderError(
                f"Muse API HTTP error {exc.code}."
            ) from exc
        except TimeoutError as exc:
            raise MuseProviderTimeoutError(
                f"Muse API request timed out after {timeout_seconds}s."
            ) from exc
        except urllib.error.URLError as exc:
            if "timed out" in str(exc.reason).lower():
                raise MuseProviderTimeoutError(
                    f"Muse API request timed out after {timeout_seconds}s."
                ) from exc
            raise MuseProviderError(
                f"Muse API network error ({type(exc.reason).__name__})."
            ) from exc
        except Exception as exc:
            raise MuseProviderError(
                f"Invalid response from Muse API ({type(exc).__name__})."
            ) from exc


class MuseApiClient:
    """Backend-only Muse API client implementing `RuntimeModelPort`.

    Uses the documented JSON Schema structured-output format:
      `response_format = {"type": "json_schema", "json_schema": {"name": ..., "schema": ...}}`
    and `max_completion_tokens`.
    """

    def __init__(
        self,
        config: RuntimeServiceConfig,
        *,
        transport: MuseProviderTransportPort | None = None,
    ) -> None:
        self._config = config
        self._transport = transport or OpenAICompatibleMuseHttpTransport()

    @staticmethod
    def _extract_json_object(raw_content: Any) -> dict[str, Any]:
        if isinstance(raw_content, Mapping):
            return dict(raw_content)
        text = str(raw_content or "").strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
            text = re.sub(r"\s*```$", "", text)
        parsed = json.loads(text)
        if not isinstance(parsed, Mapping):
            raise ValueError("Model response JSON root must be an object.")
        return dict(parsed)

    @staticmethod
    def _strictify_json_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
        """Converts a JSON schema into the provider's strict structured-output form:
        every object sets additionalProperties=false and lists every property as
        required (optional fields stay typed via anyOf [... , null])."""
        import copy as _copy

        def strictify(node: Any) -> Any:
            if isinstance(node, list):
                return [strictify(item) for item in node]
            if not isinstance(node, Mapping):
                return node
            out = {k: strictify(v) for k, v in node.items()}
            props = out.get("properties")
            if isinstance(props, Mapping) and props:
                out["additionalProperties"] = False
                out["required"] = sorted(props.keys())
            for key in ("anyOf", "oneOf", "allOf", "prefixItems", "items"):
                if key in out:
                    out[key] = strictify(out[key])
            if isinstance(out.get("$defs"), Mapping):
                out["$defs"] = {
                    name: strictify(sub) for name, sub in out["$defs"].items()
                }
            return out

        return strictify(_copy.deepcopy(dict(schema)))

    def complete_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        output_schema: dict[str, Any],
        model_id: str,
        effort: str,
        max_tokens: int,
        schema_name: str = "adaptos_application_output",
        conversation_history: Sequence[Mapping[str, str]] = (),
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        messages: list[dict[str, str]] = [
            {"role": "system", "content": system_prompt}
        ]
        for turn in conversation_history:
            r = str(turn.get("role", "user"))
            c = str(turn.get("content", ""))
            if r in ("user", "assistant") and c.strip():
                messages.append({"role": r, "content": c})
        messages.append({"role": "user", "content": user_prompt})

        safe_schema_name = re.sub(r"[^A-Za-z0-9_\-]", "_", schema_name)[:64] or "adaptos_output"
        payload: dict[str, Any] = {
            "model": model_id,
            "messages": messages,
            "max_completion_tokens": int(max_tokens),
            "temperature": 0.0,
            "reasoning_effort": effort,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": safe_schema_name,
                    "schema": self._strictify_json_schema(output_schema),
                    "strict": True,
                },
            },
        }
        effective_timeout = (
            float(timeout_seconds)
            if timeout_seconds is not None
            else self._config.muse_request_timeout_seconds
        )
        raw_response = self._transport.create_chat_completion(
            base_url=self._config.muse_api_base_url,
            api_key=self._config.muse_api_key,
            payload=payload,
            timeout_seconds=effective_timeout,
        )

        try:
            if "output" in raw_response and isinstance(
                raw_response["output"], Mapping
            ):
                return dict(raw_response["output"])
            choices = raw_response.get("choices")
            if isinstance(choices, list) and choices:
                msg = choices[0].get("message", {})
                if isinstance(msg, Mapping):
                    if isinstance(msg.get("parsed"), Mapping):
                        return dict(msg["parsed"])
                    return self._extract_json_object(msg.get("content"))
            raise ValueError("Missing 'choices[0].message.content' in Muse response.")
        except Exception as exc:
            raise MuseProviderError(
                f"Muse API returned malformed structured output: {type(exc).__name__}",
                code="muse_invalid_response",
            ) from exc

    async def acomplete_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        output_schema: dict[str, Any],
        model_id: str,
        effort: str,
        max_tokens: int,
        schema_name: str = "adaptos_application_output",
        conversation_history: Sequence[Mapping[str, str]] = (),
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        return await asyncio.to_thread(
            self.complete_json,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            output_schema=output_schema,
            model_id=model_id,
            effort=effort,
            max_tokens=max_tokens,
            schema_name=schema_name,
            conversation_history=conversation_history,
            timeout_seconds=timeout_seconds,
        )


class _SessionBoundModelPort:
    """Binds application system instructions, timeout limits, and conversation history
    to `MuseApiClient` during a single `AppRuntime.execute_bundle()` call.
    """

    def __init__(
        self,
        muse_client: MuseApiClient,
        *,
        app_id: str,
        app_system_instructions: str,
        conversation_history: Sequence[Mapping[str, str]],
        timeout_seconds: float,
    ) -> None:
        self._muse = muse_client
        self._app_id = app_id
        self._app_sys = app_system_instructions.strip()
        self._history = tuple(conversation_history)
        self._timeout_s = timeout_seconds

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
        combined_sys = (
            f"{system_prompt.strip()}\n\n=== APPLICATION SYSTEM INSTRUCTIONS ===\n{self._app_sys}"
            if self._app_sys
            else system_prompt
        )
        return self._muse.complete_json(
            system_prompt=combined_sys,
            user_prompt=user_prompt,
            output_schema=output_schema,
            model_id=model_id,
            effort=effort,
            max_tokens=max_tokens,
            schema_name=f"{self._app_id}_output",
            conversation_history=self._history,
            timeout_seconds=self._timeout_s,
        )


# =========================================================================== #
# 5. B & C. RUNTIME PROVISIONER & APPLICATION RUNTIME MANAGER
# =========================================================================== #


@dataclass
class _ProvisionedAppInstance:
    app_id: str
    project_run_id: str
    owner_id: str
    state: RuntimeLifecycleState
    delivery_package: DeliveryPackage
    bundle_files: dict[str, bytes]
    assets: tuple[SourceAssetInput, ...]
    app_config: ApplicationSpecificConfig
    app_storage: StorageService
    sandbox_verifier: SandboxVerifier
    error_code: str | None
    error_message: str | None
    provisioned_at: datetime
    updated_at: datetime


class ApplicationRuntimeManager:
    """Manages application provisioning, isolated version-scoped storage, crash recovery,
    and the 7-state lifecycle:
    VERIFIED -> PROVISIONING -> READY -> ACTIVE <-> STOPPED -> DEACTIVATED (or FAILED).
    """

    def __init__(
        self,
        config: RuntimeServiceConfig,
        package_manager: ApplicationPackageManager,
        *,
        docker_runner_override: Callable[..., Any] | None = None,
    ) -> None:
        self.config = config
        self.package_manager = package_manager
        self.docker_runner_override = docker_runner_override
        self._lock = threading.RLock()
        self.runtime_root = Path(config.runtime_data_root).resolve()
        self.runtime_root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.runtime_root / "runtime_catalog.db"
        self.apps_root = self.runtime_root / "apps"
        self.apps_root.mkdir(parents=True, exist_ok=True)
        self._instances: dict[str, _ProvisionedAppInstance] = {}
        self._init_db()
        self._reload_persisted_apps()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS runtime_applications (
                    app_id TEXT PRIMARY KEY,
                    project_run_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    delivery_package_json TEXT NOT NULL,
                    bundle_files_hex_json TEXT NOT NULL,
                    assets_json TEXT NOT NULL,
                    app_config_json TEXT NOT NULL,
                    error_code TEXT,
                    error_message TEXT,
                    provisioned_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)

    def _resolve_version_storage_dir(
        self, app_id: str, version_id: str, artifact_hash: str
    ) -> Path:
        safe_app_id = validate_safe_identifier(app_id, field_name="app_id")
        safe_ver = validate_safe_identifier(version_id, field_name="version_id")
        safe_hash_prefix = validate_safe_identifier(
            artifact_hash[:16], field_name="artifact_hash"
        )
        version_folder = f"{safe_ver}_{safe_hash_prefix}"
        return _resolve_contained_path(
            self.apps_root, safe_app_id, "versions", version_folder, "storage"
        )

    def _persist_instance(self, inst: _ProvisionedAppInstance) -> None:
        files_hex = {p: raw.hex() for p, raw in inst.bundle_files.items()}
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO runtime_applications
                (app_id, project_run_id, owner_id, state, delivery_package_json,
                 bundle_files_hex_json, assets_json, app_config_json,
                 error_code, error_message, provisioned_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    inst.app_id,
                    inst.project_run_id,
                    inst.owner_id,
                    inst.state.value,
                    _canonical_bytes(
                        inst.delivery_package.model_dump(mode="json")
                    ).decode("utf-8"),
                    _canonical_bytes(files_hex).decode("utf-8"),
                    _canonical_bytes(
                        [a.model_dump(mode="json") for a in inst.assets]
                    ).decode("utf-8"),
                    _canonical_bytes(
                        inst.app_config.model_dump(mode="json")
                    ).decode("utf-8"),
                    inst.error_code,
                    inst.error_message,
                    inst.provisioned_at.isoformat(),
                    inst.updated_at.isoformat(),
                ),
            )

    def _reload_persisted_apps(self) -> None:
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM runtime_applications").fetchall()

        for r in rows:
            app_id = validate_safe_identifier(str(r["app_id"]), field_name="app_id")
            pkg = DeliveryPackage.model_validate(
                json.loads(r["delivery_package_json"])
            )
            files_hex = json.loads(r["bundle_files_hex_json"])
            bundle_files = {k: bytes.fromhex(v) for k, v in files_hex.items()}
            assets = tuple(
                SourceAssetInput.model_validate(a)
                for a in json.loads(r["assets_json"])
            )
            app_cfg = ApplicationSpecificConfig.model_validate(
                json.loads(r["app_config_json"])
            )
            app_dir = self._resolve_version_storage_dir(
                app_id, app_cfg.version_id, app_cfg.artifact_hash
            )
            app_storage = StorageService(StorageConfig(app_dir))
            app_storage.initialize()
            sbx_verifier = self._create_scoped_verifier(app_cfg.limits)

            persisted_state = RuntimeLifecycleState(str(r["state"]))
            err_code = r["error_code"]
            err_msg = r["error_message"]

            # Section 6: If the process crashed while an application was in PROVISIONING,
            # preserve it in PROVISIONING with an explicit crash-interrupted marker so
            # recover_application() can safely re-verify and finish provisioning.
            if persisted_state == RuntimeLifecycleState.PROVISIONING and not err_code:
                err_code = "interrupted_provisioning"
                err_msg = (
                    "Application was left in PROVISIONING after an unexpected restart; "
                    "invoke recover_application() to re-verify and complete provisioning."
                )

            self._instances[app_id] = _ProvisionedAppInstance(
                app_id=app_id,
                project_run_id=validate_safe_identifier(
                    str(r["project_run_id"]), field_name="project_run_id"
                ),
                owner_id=validate_safe_identifier(
                    str(r["owner_id"]), field_name="owner_id"
                ),
                state=persisted_state,
                delivery_package=pkg,
                bundle_files=bundle_files,
                assets=assets,
                app_config=app_cfg,
                app_storage=app_storage,
                sandbox_verifier=sbx_verifier,
                error_code=err_code,
                error_message=err_msg,
                provisioned_at=datetime.fromisoformat(str(r["provisioned_at"])),
                updated_at=datetime.fromisoformat(str(r["updated_at"])),
            )

    def _create_scoped_verifier(self, limits: RuntimeLimits) -> SandboxVerifier:
        sbx_cfg = SandboxConfig(
            sandbox_timeout_seconds=max(1, int(limits.wall_seconds)),
            sandbox_memory_mb=max(32, int(limits.memory_mb)),
            prefer_docker_sandbox=True,
            allow_subprocess_dev_fallback=self.config.allow_subprocess_sandbox_fallback,
        )
        return SandboxVerifier(
            sbx_cfg, docker_runner_override=self.docker_runner_override
        )

    def _validate_owner_access(self, owner_id: str) -> str:
        clean_owner = validate_safe_identifier(owner_id, field_name="owner_id")
        if (
            self.config.enforce_single_owner_mode
            and clean_owner != self.config.default_owner_id
        ):
            raise RuntimeAuthorizationError(
                f"Single-owner MVP mode is active; owner_id must be '{self.config.default_owner_id}'."
            )
        return clean_owner

    @staticmethod
    def _to_summary(inst: _ProvisionedAppInstance) -> RuntimeApplicationSummary:
        return RuntimeApplicationSummary(
            app_id=inst.app_id,
            project_run_id=inst.project_run_id,
            owner_id=inst.owner_id,
            version_id=inst.app_config.version_id,
            artifact_hash=inst.app_config.artifact_hash,
            spec_hash=inst.app_config.spec_hash,
            verdict_id=inst.delivery_package.verdict.signing_key_id,
            verdict_status="ready",
            architecture=inst.app_config.architecture,
            runtime_model=inst.app_config.runtime_model,
            goal=inst.app_config.goal,
            state=inst.state,
            uses_retrieval=inst.app_config.uses_retrieval,
            uses_sandboxed_tools=inst.app_config.uses_sandboxed_tools,
            ingested_asset_count=len(inst.assets),
            error_code=inst.error_code,
            error_message=inst.error_message,
            provisioned_at=inst.provisioned_at,
            updated_at=inst.updated_at,
        )

    def provision_from_zip(
        self,
        zip_payload: bytes | Path | io.BytesIO,
        *,
        project_run_id: str,
        owner_id: str = DEFAULT_RUNTIME_OWNER_ID,
        app_id: str | None = None,
        assets: Sequence[SourceAssetInput] = (),
        auto_activate: bool = True,
    ) -> RuntimeApplicationSummary:
        clean_owner = self._validate_owner_access(owner_id)
        clean_run_id = validate_safe_identifier(
            project_run_id, field_name="project_run_id"
        )
        resolved_app_id = validate_safe_identifier(
            app_id or f"app_{clean_run_id}", field_name="app_id"
        )

        with self._lock:
            existing = self._instances.get(resolved_app_id)
            if existing is not None:
                if existing.owner_id != clean_owner:
                    raise RuntimeAuthorizationError(
                        "Cannot provision or update an application owned by another user."
                    )
                if existing.project_run_id != clean_run_id:
                    raise RuntimeAuthorizationError(
                        f"Application '{resolved_app_id}' is bound to project '{existing.project_run_id}', not '{clean_run_id}'."
                    )

            # Stage 1: Validate ZIP archive & verify Verdict -> VERIFIED
            verified = self.package_manager.extract_and_verify_zip(
                zip_payload,
                project_run_id=clean_run_id,
                app_id=resolved_app_id,
                external_assets=assets,
            )

            # Section 2 Storage Safety & Idempotency:
            # If the exact same artifact_hash is already provisioned in READY or ACTIVE
            # with the same assets, return idempotently without wiping storage or conversations!
            if (
                existing is not None
                and existing.app_config.artifact_hash
                == verified.app_config.artifact_hash
                and existing.app_config.version_id == verified.app_config.version_id
                and existing.state
                in (RuntimeLifecycleState.READY, RuntimeLifecycleState.ACTIVE)
                and existing.assets == verified.bundled_assets
            ):
                if auto_activate and existing.state == RuntimeLifecycleState.READY:
                    existing.state = RuntimeLifecycleState.ACTIVE
                    existing.updated_at = _now_utc()
                    self._persist_instance(existing)
                return self._to_summary(existing)

            now = _now_utc()
            # Provision in a version-scoped directory so existing application storage
            # and conversations are never destructively deleted.
            app_dir = self._resolve_version_storage_dir(
                resolved_app_id,
                verified.app_config.version_id,
                verified.app_config.artifact_hash,
            )
            app_storage = StorageService(StorageConfig(app_dir))
            app_storage.initialize()
            sbx_verifier = self._create_scoped_verifier(
                verified.app_config.limits
            )

            inst = _ProvisionedAppInstance(
                app_id=resolved_app_id,
                project_run_id=clean_run_id,
                owner_id=clean_owner,
                state=RuntimeLifecycleState.VERIFIED,
                delivery_package=verified.delivery_package,
                bundle_files=verified.bundle_files,
                assets=verified.bundled_assets,
                app_config=verified.app_config,
                app_storage=app_storage,
                sandbox_verifier=sbx_verifier,
                error_code=None,
                error_message=None,
                provisioned_at=existing.provisioned_at if existing else now,
                updated_at=now,
            )
            self._instances[resolved_app_id] = inst
            self._persist_instance(inst)

            # Stage 2: Transition VERIFIED -> PROVISIONING
            inst.state = RuntimeLifecycleState.PROVISIONING
            inst.updated_at = _now_utc()
            self._persist_instance(inst)

            try:
                self._provision_environment_and_dependencies(inst)
            except Exception as exc:
                inst.state = RuntimeLifecycleState.FAILED
                inst.error_code = (
                    exc.code
                    if isinstance(exc, RuntimeServiceError)
                    else "provisioning_failed"
                )
                inst.error_message = str(exc)[:300]
                inst.updated_at = _now_utc()
                self._persist_instance(inst)
                raise

            # Stage 3: Transition PROVISIONING -> READY (and optionally -> ACTIVE)
            inst.state = RuntimeLifecycleState.READY
            inst.updated_at = _now_utc()
            self._persist_instance(inst)

            if auto_activate:
                inst.state = RuntimeLifecycleState.ACTIVE
                inst.updated_at = _now_utc()
                self._persist_instance(inst)

            return self._to_summary(inst)

    def _provision_environment_and_dependencies(
        self, inst: _ProvisionedAppInstance
    ) -> None:
        cfg = inst.app_config

        if cfg.uses_sandboxed_tools:
            if (
                not inst.sandbox_verifier._docker_available()
                and not self.config.allow_subprocess_sandbox_fallback
            ):
                raise ProvisioningError(
                    "Docker sandbox is unavailable and allow_subprocess_sandbox_fallback is False; "
                    "failing closed for tool_use application.",
                    code="sandbox_unavailable",
                )
            for st in cfg.steps:
                if st.component_ref.startswith("fn.sandboxed@"):
                    target_ref = str(st.config["target_component_ref"])
                    t_id, t_ver = target_ref.split("@", 1)
                    fn_path = f"generated/{t_id}/{t_ver}/fn.py"
                    code_str = inst.bundle_files[fn_path].decode("utf-8")
                    ast_ok, sig_ok, lint_err = (
                        SandboxVerifier.lint_ast_and_signature(code_str)
                    )
                    if not (ast_ok and sig_ok):
                        raise ProvisioningError(
                            f"Generated component '{target_ref}' failed AST/signature verification: {lint_err}",
                            code="invalid_generated_component",
                        )

        if cfg.uses_retrieval:
            for st in cfg.steps:
                if st.component_ref.startswith("doc.ingest@"):
                    fts_app_id = validate_safe_identifier(
                        str(st.config["app_id"]), field_name="doc.ingest.app_id"
                    )
                    inst.app_storage.provision_app_storage(
                        {
                            "project_id": inst.project_run_id,
                            "app_id": fts_app_id,
                            "resources": [
                                {
                                    "name": "fts-index",
                                    "kind": "database",
                                    "backend": "fts5",
                                    "rel_path": "app.db",
                                    "schema_version": "1",
                                }
                            ],
                        }
                    )
                    chunk_size = int(st.config.get("chunk_size", 500))
                    overlap = int(st.config.get("overlap", 50))
                    allowed_formats = st.config.get(
                        "formats", ["txt", "md", "csv", "json"]
                    )
                    for asset in inst.assets:
                        chunks = AppRuntime._parse_and_chunk_asset(
                            asset,
                            allowed_formats=allowed_formats,
                            chunk_size=chunk_size,
                            overlap=overlap,
                        )
                        for chunk_id, chunk_text in chunks:
                            inst.app_storage.add_fts5_document(
                                fts_app_id, chunk_id, chunk_text
                            )

    def _get_authorized_instance(
        self, app_id: str, owner_id: str
    ) -> _ProvisionedAppInstance:
        safe_app_id = validate_safe_identifier(app_id, field_name="app_id")
        clean_owner = self._validate_owner_access(owner_id)
        with self._lock:
            if safe_app_id not in self._instances:
                raise KeyError(f"Runtime application '{safe_app_id}' not found.")
            inst = self._instances[safe_app_id]
            if inst.owner_id != clean_owner:
                raise RuntimeAuthorizationError(
                    f"Owner '{clean_owner}' is not authorized for application '{safe_app_id}'."
                )
            return inst

    def get_status(
        self, app_id: str, *, owner_id: str = DEFAULT_RUNTIME_OWNER_ID
    ) -> RuntimeApplicationSummary:
        inst = self._get_authorized_instance(app_id, owner_id)
        return self._to_summary(inst)

    def get_application_config(
        self, app_id: str, *, owner_id: str = DEFAULT_RUNTIME_OWNER_ID
    ) -> ApplicationSpecificConfig:
        inst = self._get_authorized_instance(app_id, owner_id)
        return inst.app_config

    def activate_application(
        self, app_id: str, *, owner_id: str = DEFAULT_RUNTIME_OWNER_ID
    ) -> RuntimeApplicationSummary:
        with self._lock:
            inst = self._get_authorized_instance(app_id, owner_id)
            if inst.state == RuntimeLifecycleState.ACTIVE:
                return self._to_summary(inst)
            if inst.state not in (
                RuntimeLifecycleState.READY,
                RuntimeLifecycleState.STOPPED,
            ):
                raise LifecycleStateError(
                    f"Cannot activate application '{app_id}' from state '{inst.state.value}'; "
                    "must be in READY or STOPPED."
                )
            # Re-verify full package & Verdict authenticity before activating
            _ = self.package_manager.verify_delivery_package_and_files(
                delivery_package=inst.delivery_package,
                bundle_files=inst.bundle_files,
                project_run_id=inst.project_run_id,
                app_id=inst.app_id,
                assets=inst.assets,
            )
            inst.state = RuntimeLifecycleState.ACTIVE
            inst.updated_at = _now_utc()
            self._persist_instance(inst)
            return self._to_summary(inst)

    def stop_application(
        self, app_id: str, *, owner_id: str = DEFAULT_RUNTIME_OWNER_ID
    ) -> RuntimeApplicationSummary:
        with self._lock:
            inst = self._get_authorized_instance(app_id, owner_id)
            if inst.state == RuntimeLifecycleState.STOPPED:
                return self._to_summary(inst)
            if inst.state != RuntimeLifecycleState.ACTIVE:
                raise LifecycleStateError(
                    f"Cannot stop application '{app_id}' from state '{inst.state.value}'; must be ACTIVE."
                )
            inst.state = RuntimeLifecycleState.STOPPED
            inst.updated_at = _now_utc()
            self._persist_instance(inst)
            return self._to_summary(inst)

    def deactivate_application(
        self, app_id: str, *, owner_id: str = DEFAULT_RUNTIME_OWNER_ID
    ) -> RuntimeApplicationSummary:
        with self._lock:
            inst = self._get_authorized_instance(app_id, owner_id)
            if inst.state == RuntimeLifecycleState.DEACTIVATED:
                return self._to_summary(inst)
            if inst.state not in (
                RuntimeLifecycleState.READY,
                RuntimeLifecycleState.ACTIVE,
                RuntimeLifecycleState.STOPPED,
            ):
                raise LifecycleStateError(
                    f"Cannot deactivate application '{app_id}' from state '{inst.state.value}'."
                )
            inst.state = RuntimeLifecycleState.DEACTIVATED
            inst.updated_at = _now_utc()
            self._persist_instance(inst)
            return self._to_summary(inst)

    def recover_application(
        self,
        app_id: str,
        *,
        owner_id: str = DEFAULT_RUNTIME_OWNER_ID,
        auto_activate: bool = True,
    ) -> RuntimeApplicationSummary:
        """Section 6: Safely recovers an application left in PROVISIONING after a crash,
        or in FAILED, DEACTIVATED, or STOPPED.

        Always re-verifies the signed Verdict, Spec hash, and bundle file hashes first
        so recovery can never accidentally activate an invalid or tampered package.
        """
        with self._lock:
            inst = self._get_authorized_instance(app_id, owner_id)
            if inst.state not in (
                RuntimeLifecycleState.PROVISIONING,
                RuntimeLifecycleState.FAILED,
                RuntimeLifecycleState.DEACTIVATED,
                RuntimeLifecycleState.STOPPED,
            ):
                raise LifecycleStateError(
                    f"Recovery is only valid for PROVISIONING, FAILED, DEACTIVATED, or STOPPED "
                    f"applications (current: '{inst.state.value}')."
                )
            inst.state = RuntimeLifecycleState.PROVISIONING
            inst.error_code = None
            inst.error_message = None
            inst.updated_at = _now_utc()
            self._persist_instance(inst)

            try:
                verified = self.package_manager.verify_delivery_package_and_files(
                    delivery_package=inst.delivery_package,
                    bundle_files=inst.bundle_files,
                    project_run_id=inst.project_run_id,
                    app_id=inst.app_id,
                    assets=inst.assets,
                )
                inst.app_config = verified.app_config
                self._provision_environment_and_dependencies(inst)
            except Exception as exc:
                inst.state = RuntimeLifecycleState.FAILED
                inst.error_code = (
                    exc.code
                    if isinstance(exc, RuntimeServiceError)
                    else "recovery_failed"
                )
                inst.error_message = str(exc)[:300]
                inst.updated_at = _now_utc()
                self._persist_instance(inst)
                raise

            inst.state = RuntimeLifecycleState.READY
            inst.updated_at = _now_utc()
            self._persist_instance(inst)

            if auto_activate:
                inst.state = RuntimeLifecycleState.ACTIVE
                inst.updated_at = _now_utc()
                self._persist_instance(inst)

            return self._to_summary(inst)


# =========================================================================== #
# 6. F. CONVERSATION AND SESSION MANAGER (Latest-N Chronological & Isolated)
# =========================================================================== #


class ConversationSessionManager:
    """Persists multi-turn sessions and messages in SQLite with strict
    `(app_id, project_run_id, owner_id, session_id)` isolation.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS runtime_sessions (
                    session_id TEXT PRIMARY KEY,
                    app_id TEXT NOT NULL,
                    project_run_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_runtime_sessions_app_owner
                    ON runtime_sessions(app_id, owner_id);

                CREATE TABLE IF NOT EXISTS runtime_messages (
                    message_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    app_id TEXT NOT NULL,
                    project_run_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    structured_payload_json TEXT NOT NULL,
                    source_references_json TEXT NOT NULL,
                    step_traces_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_runtime_messages_session
                    ON runtime_messages(session_id, created_at);
            """)

    def create_session(
        self,
        *,
        app_id: str,
        project_run_id: str,
        owner_id: str,
        title: str | None = None,
        session_id: str | None = None,
    ) -> ConversationSessionSummary:
        safe_app_id = validate_safe_identifier(app_id, field_name="app_id")
        safe_run_id = validate_safe_identifier(
            project_run_id, field_name="project_run_id"
        )
        safe_owner = validate_safe_identifier(owner_id, field_name="owner_id")
        sid = validate_safe_identifier(
            session_id or f"sess_{uuid.uuid4().hex[:12]}",
            field_name="session_id",
        )
        clean_title = (title or "Adapted AI Conversation").strip()[:120]
        now = _now_utc()

        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            existing = conn.execute(
                "SELECT 1 FROM runtime_sessions WHERE session_id=?", (sid,)
            ).fetchone()
            if existing is not None:
                raise RuntimeServiceError(
                    f"Session '{sid}' already exists.", code="duplicate_session_id"
                )
            conn.execute(
                """
                INSERT INTO runtime_sessions
                (session_id, app_id, project_run_id, owner_id, title, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sid,
                    safe_app_id,
                    safe_run_id,
                    safe_owner,
                    clean_title,
                    now.isoformat(),
                    now.isoformat(),
                ),
            )

        return ConversationSessionSummary(
            session_id=sid,
            app_id=safe_app_id,
            owner_id=safe_owner,
            title=clean_title,
            message_count=0,
            created_at=now,
            updated_at=now,
        )

    def get_session(
        self,
        *,
        app_id: str,
        project_run_id: str,
        session_id: str,
        owner_id: str,
    ) -> ConversationSessionSummary:
        safe_app_id = validate_safe_identifier(app_id, field_name="app_id")
        safe_run_id = validate_safe_identifier(
            project_run_id, field_name="project_run_id"
        )
        safe_sid = validate_safe_identifier(session_id, field_name="session_id")
        safe_owner = validate_safe_identifier(owner_id, field_name="owner_id")

        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM runtime_sessions WHERE session_id=?",
                (safe_sid,),
            ).fetchone()
            if row is None:
                raise KeyError(f"Session '{safe_sid}' not found.")
            if (
                str(row["app_id"]) != safe_app_id
                or str(row["project_run_id"]) != safe_run_id
                or str(row["owner_id"]) != safe_owner
            ):
                raise RuntimeAuthorizationError(
                    "Access denied: session belongs to a different application, project, or owner."
                )
            cnt_row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM runtime_messages WHERE session_id=?",
                (safe_sid,),
            ).fetchone()
            msg_count = int(cnt_row["cnt"]) if cnt_row else 0

        return ConversationSessionSummary(
            session_id=str(row["session_id"]),
            app_id=str(row["app_id"]),
            owner_id=str(row["owner_id"]),
            title=str(row["title"]),
            message_count=msg_count,
            created_at=datetime.fromisoformat(str(row["created_at"])),
            updated_at=datetime.fromisoformat(str(row["updated_at"])),
        )

    def list_sessions(
        self, *, app_id: str, project_run_id: str, owner_id: str
    ) -> tuple[ConversationSessionSummary, ...]:
        safe_app_id = validate_safe_identifier(app_id, field_name="app_id")
        safe_run_id = validate_safe_identifier(
            project_run_id, field_name="project_run_id"
        )
        safe_owner = validate_safe_identifier(owner_id, field_name="owner_id")

        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT s.*,
                       (SELECT COUNT(*) FROM runtime_messages m WHERE m.session_id = s.session_id) AS msg_count
                FROM runtime_sessions s
                WHERE s.app_id = ? AND s.project_run_id = ? AND s.owner_id = ?
                ORDER BY s.updated_at DESC
                """,
                (safe_app_id, safe_run_id, safe_owner),
            ).fetchall()

        return tuple(
            ConversationSessionSummary(
                session_id=str(r["session_id"]),
                app_id=str(r["app_id"]),
                owner_id=str(r["owner_id"]),
                title=str(r["title"]),
                message_count=int(r["msg_count"]),
                created_at=datetime.fromisoformat(str(r["created_at"])),
                updated_at=datetime.fromisoformat(str(r["updated_at"])),
            )
            for r in rows
        )

    def get_conversation_history(
        self,
        *,
        app_id: str,
        project_run_id: str,
        session_id: str,
        owner_id: str,
        limit: int = 100,
    ) -> tuple[ConversationMessage, ...]:
        """Section 4: Retrieves the LATEST `limit` messages and returns them in
        chronological order (oldest-to-newest among the latest `limit` messages).
        """
        _ = self.get_session(
            app_id=app_id,
            project_run_id=project_run_id,
            session_id=session_id,
            owner_id=owner_id,
        )
        safe_limit = max(1, int(limit))
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT * FROM (
                    SELECT m.*, m.rowid AS _rid
                    FROM runtime_messages m
                    WHERE m.session_id = ? AND m.app_id = ? AND m.project_run_id = ? AND m.owner_id = ?
                    ORDER BY m.created_at DESC, m.rowid DESC
                    LIMIT ?
                ) recent
                ORDER BY recent.created_at ASC, recent._rid ASC
                """,
                (session_id, app_id, project_run_id, owner_id, safe_limit),
            ).fetchall()

        return tuple(
            ConversationMessage(
                message_id=str(r["message_id"]),
                session_id=str(r["session_id"]),
                app_id=str(r["app_id"]),
                role=r["role"],
                content=str(r["content"]),
                structured_payload=json.loads(r["structured_payload_json"]),
                source_references=tuple(
                    SourceReference.model_validate(sr)
                    for sr in json.loads(r["source_references_json"])
                ),
                step_traces=tuple(
                    StepTrace.model_validate(st)
                    for st in json.loads(r["step_traces_json"])
                ),
                created_at=datetime.fromisoformat(str(r["created_at"])),
            )
            for r in rows
        )

    def append_message(
        self,
        *,
        app_id: str,
        project_run_id: str,
        session_id: str,
        owner_id: str,
        role: Literal["user", "assistant"],
        content: str,
        structured_payload: Mapping[str, Any] | None = None,
        source_references: Sequence[SourceReference] = (),
        step_traces: Sequence[StepTrace] = (),
    ) -> ConversationMessage:
        _ = self.get_session(
            app_id=app_id,
            project_run_id=project_run_id,
            session_id=session_id,
            owner_id=owner_id,
        )
        msg_id = f"msg_{uuid.uuid4().hex[:12]}"
        now = _now_utc()
        payload_dict = dict(structured_payload or {})

        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute(
                """
                INSERT INTO runtime_messages
                (message_id, session_id, app_id, project_run_id, owner_id, role, content,
                 structured_payload_json, source_references_json, step_traces_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    msg_id,
                    session_id,
                    app_id,
                    project_run_id,
                    owner_id,
                    role,
                    content,
                    _canonical_bytes(payload_dict).decode("utf-8"),
                    _canonical_bytes(
                        [sr.model_dump(mode="json") for sr in source_references]
                    ).decode("utf-8"),
                    _canonical_bytes(
                        [st.model_dump(mode="json") for st in step_traces]
                    ).decode("utf-8"),
                    now.isoformat(),
                ),
            )
            conn.execute(
                "UPDATE runtime_sessions SET updated_at=? WHERE session_id=?",
                (now.isoformat(), session_id),
            )

        return ConversationMessage(
            message_id=msg_id,
            session_id=session_id,
            app_id=app_id,
            role=role,
            content=content,
            structured_payload=payload_dict,
            source_references=tuple(source_references),
            step_traces=tuple(step_traces),
            created_at=now,
        )


# =========================================================================== #
# 7. G. CHAT EXECUTION PIPELINE & UNIFIED RUNTIME SERVICE FACADE
# =========================================================================== #


class AdaptOSRuntimeService:
    """Unified Generic Runtime Backend for AdaptOS."""

    def __init__(
        self,
        config: RuntimeServiceConfig,
        *,
        muse_transport: MuseProviderTransportPort | None = None,
        docker_runner_override: Callable[..., Any] | None = None,
    ) -> None:
        self.config = config
        self.package_manager = ApplicationPackageManager(config)
        self.app_manager = ApplicationRuntimeManager(
            config,
            self.package_manager,
            docker_runner_override=docker_runner_override,
        )
        self.session_manager = ConversationSessionManager(
            self.app_manager.db_path
        )
        self.muse_client = MuseApiClient(config, transport=muse_transport)

    # ----------------------------------------------------------------------- #
    # Lifecycle & Provisioning Operations
    # ----------------------------------------------------------------------- #
    def provision_application(
        self,
        zip_payload: bytes | Path | io.BytesIO,
        *,
        project_run_id: str,
        owner_id: str = DEFAULT_RUNTIME_OWNER_ID,
        app_id: str | None = None,
        assets: Sequence[SourceAssetInput] = (),
        auto_activate: bool = True,
    ) -> RuntimeApplicationSummary:
        return self.app_manager.provision_from_zip(
            zip_payload,
            project_run_id=project_run_id,
            owner_id=owner_id,
            app_id=app_id,
            assets=assets,
            auto_activate=auto_activate,
        )

    def get_application_status(
        self, app_id: str, *, owner_id: str = DEFAULT_RUNTIME_OWNER_ID
    ) -> RuntimeApplicationSummary:
        return self.app_manager.get_status(app_id, owner_id=owner_id)

    def get_application_config(
        self, app_id: str, *, owner_id: str = DEFAULT_RUNTIME_OWNER_ID
    ) -> ApplicationSpecificConfig:
        return self.app_manager.get_application_config(app_id, owner_id=owner_id)

    def activate_application(
        self, app_id: str, *, owner_id: str = DEFAULT_RUNTIME_OWNER_ID
    ) -> RuntimeApplicationSummary:
        return self.app_manager.activate_application(app_id, owner_id=owner_id)

    def stop_application(
        self, app_id: str, *, owner_id: str = DEFAULT_RUNTIME_OWNER_ID
    ) -> RuntimeApplicationSummary:
        return self.app_manager.stop_application(app_id, owner_id=owner_id)

    def deactivate_application(
        self, app_id: str, *, owner_id: str = DEFAULT_RUNTIME_OWNER_ID
    ) -> RuntimeApplicationSummary:
        return self.app_manager.deactivate_application(app_id, owner_id=owner_id)

    def recover_application(
        self,
        app_id: str,
        *,
        owner_id: str = DEFAULT_RUNTIME_OWNER_ID,
        auto_activate: bool = True,
    ) -> RuntimeApplicationSummary:
        return self.app_manager.recover_application(
            app_id, owner_id=owner_id, auto_activate=auto_activate
        )

    # ----------------------------------------------------------------------- #
    # Session & Conversation Operations
    # ----------------------------------------------------------------------- #
    def create_chat_session(
        self,
        app_id: str,
        *,
        owner_id: str = DEFAULT_RUNTIME_OWNER_ID,
        title: str | None = None,
        session_id: str | None = None,
    ) -> ConversationSessionSummary:
        inst = self.app_manager._get_authorized_instance(app_id, owner_id)
        if inst.state not in (
            RuntimeLifecycleState.READY,
            RuntimeLifecycleState.ACTIVE,
        ):
            raise LifecycleStateError(
                f"Cannot create chat session when application '{app_id}' is in state '{inst.state.value}'."
            )
        return self.session_manager.create_session(
            app_id=inst.app_id,
            project_run_id=inst.project_run_id,
            owner_id=inst.owner_id,
            title=title or inst.app_config.goal[:80],
            session_id=session_id,
        )

    def list_chat_sessions(
        self, app_id: str, *, owner_id: str = DEFAULT_RUNTIME_OWNER_ID
    ) -> tuple[ConversationSessionSummary, ...]:
        inst = self.app_manager._get_authorized_instance(app_id, owner_id)
        return self.session_manager.list_sessions(
            app_id=inst.app_id,
            project_run_id=inst.project_run_id,
            owner_id=inst.owner_id,
        )

    def get_conversation_history(
        self,
        app_id: str,
        session_id: str,
        *,
        owner_id: str = DEFAULT_RUNTIME_OWNER_ID,
        limit: int = 100,
    ) -> tuple[ConversationMessage, ...]:
        inst = self.app_manager._get_authorized_instance(app_id, owner_id)
        return self.session_manager.get_conversation_history(
            app_id=inst.app_id,
            project_run_id=inst.project_run_id,
            session_id=session_id,
            owner_id=inst.owner_id,
            limit=limit,
        )

    # ----------------------------------------------------------------------- #
    # Section 5: Deterministic Input Mapping & Structured Validation
    # ----------------------------------------------------------------------- #
    @staticmethod
    def _extract_explicit_labeled_value(
        field_spec: FieldSpec, text: str
    ) -> tuple[bool, Any]:
        """Extracts a value from `text` ONLY when explicitly labeled with `field_spec.name`
        (e.g. `days_since_purchase: 12` or `days_since_purchase = 12`).
        Never guesses or assigns bare numbers to multiple fields.
        """
        pattern = re.compile(
            rf"\b{re.escape(field_spec.name)}\s*[:=]\s*([^\n,;]+)",
            re.IGNORECASE,
        )
        m = pattern.search(text)
        if not m:
            return False, None
        raw_val = m.group(1).strip()
        if field_spec.data_type == "integer":
            if re.fullmatch(r"-?\d+", raw_val):
                return True, int(raw_val)
            return True, raw_val  # Let schema validation report type mismatch
        if field_spec.data_type == "number":
            if re.fullmatch(r"-?\d+(?:\.\d+)?", raw_val):
                return True, float(raw_val)
            return True, raw_val
        if field_spec.data_type == "boolean":
            if raw_val.lower() in ("true", "false"):
                return True, (raw_val.lower() == "true")
            return True, raw_val
        return True, raw_val.strip("\"'")

    @classmethod
    def _resolve_and_validate_inputs(
        cls,
        *,
        app_cfg: ApplicationSpecificConfig,
        user_message: str,
        structured_inputs: Mapping[str, Any] | None,
    ) -> tuple[bool, dict[str, Any], tuple[str, ...], tuple[str, ...]]:
        """Returns `(is_valid, payload, missing_fields, validation_errors)`.

        Rules (Section 5):
        1. Never assigns a bare number in free text to multiple numeric fields.
        2. Maps `user_message` automatically to a string field ONLY when there is a single
           unambiguous string input field in `spec_inputs`.
        3. Supports explicit `structured_inputs`, JSON object messages, or explicit
           `field_name: value` / `field_name=value` labels.
        4. Validates against `app_cfg.input_json_schema` and returns structured
           `missing_fields` and `validation_errors` if anything is missing or invalid.
        """
        clean_msg = str(user_message or "").strip()
        if not clean_msg and not structured_inputs:
            req_names = tuple(
                f.name for f in app_cfg.spec_inputs if f.required
            )
            return (
                False,
                {},
                req_names,
                ("Input message and structured_inputs are both empty.",),
            )

        payload: dict[str, Any] = dict(structured_inputs or {})

        # 1. If user_message is a JSON object, merge declared input keys
        if clean_msg.startswith("{") and clean_msg.endswith("}"):
            try:
                parsed_json = json.loads(clean_msg)
                if isinstance(parsed_json, Mapping):
                    for k, v in parsed_json.items():
                        payload.setdefault(str(k), v)
            except Exception:
                pass

        # 2. Check for explicit `field_name: value` or `field_name=value` labels in user_message
        for f in app_cfg.spec_inputs:
            if f.name not in payload and clean_msg:
                found, extracted = cls._extract_explicit_labeled_value(
                    f, clean_msg
                )
                if found:
                    payload[f.name] = extracted

        # 3. Unambiguous single string input field mapping
        string_fields = [
            f.name
            for f in app_cfg.spec_inputs
            if f.data_type in ("string", "file")
        ]
        if (
            clean_msg
            and len(string_fields) == 1
            and string_fields[0] not in payload
        ):
            payload[string_fields[0]] = clean_msg

        # 4. Unambiguous single numeric field extraction ONLY when there is a single numeric
        # field in the entire Spec AND a single number in the message
        numeric_fields = [
            f for f in app_cfg.spec_inputs if f.data_type in ("integer", "number")
        ]
        if (
            clean_msg
            and len(numeric_fields) == 1
            and numeric_fields[0].name not in payload
        ):
            nf = numeric_fields[0]
            all_nums = re.findall(r"(?<![A-Za-z0-9_])-?\d+(?:\.\d+)?(?![A-Za-z0-9_])", clean_msg)
            if len(all_nums) == 1:
                num_tok = all_nums[0]
                if nf.data_type == "integer" and re.fullmatch(r"-?\d+", num_tok):
                    payload[nf.name] = int(num_tok)
                elif nf.data_type == "number":
                    payload[nf.name] = float(num_tok)

        # 5. Identify missing required fields
        missing: list[str] = [
            f.name
            for f in app_cfg.spec_inputs
            if f.required and f.name not in payload
        ]

        # 6. Validate against the application's declared input_json_schema
        schema_errs = SandboxVerifier.validate_output_against_schema(
            payload, app_cfg.input_json_schema
        )

        if missing or schema_errs:
            return False, payload, tuple(missing), tuple(schema_errs)

        return True, payload, (), ()

    # ----------------------------------------------------------------------- #
    # Section 7: Genuine Citation Verification & Source Provenance Preservation
    # ----------------------------------------------------------------------- #
    @staticmethod
    def _resolve_asset_provenance(
        chunk_doc_id: str, assets: Sequence[SourceAssetInput]
    ) -> tuple[str | None, str | None]:
        """Maps an FTS5 chunk doc_id (e.g. `pol_v1_c0`) back to its original `(asset_id, filename)`."""
        for a in assets:
            if chunk_doc_id == a.asset_id or any(
                chunk_doc_id.startswith(f"{a.asset_id}{sep}")
                for sep in ("_c", "_json_", "_csv_")
            ):
                return a.asset_id, a.filename
        return None, None

    @classmethod
    def _collect_source_references(
        cls,
        *,
        app_runtime: AppRuntime,
        app_cfg: ApplicationSpecificConfig,
        assets: Sequence[SourceAssetInput],
        input_payload: Mapping[str, Any],
        output_payload: Mapping[str, Any],
        step_traces: Sequence[StepTrace],
    ) -> tuple[SourceReference, ...]:
        """Section 7: Returns source references with original asset provenance, and marks
        `citation_verified=True` ONLY when both `retrieve.lexical` and `cite.verify`
        succeeded in `step_traces` and the specific passage matches the cited text.
        """
        if not app_cfg.uses_retrieval or not app_cfg.retrieval_step_config:
            return ()

        retrieval_step_ok = any(
            st.component_ref.startswith("retrieve.lexical@")
            and st.status == "ok"
            and "empty_retrieval" not in st.output_keys
            for st in step_traces
        )
        if not retrieval_step_ok:
            return ()

        cite_verify_step_ok = any(
            st.component_ref.startswith("cite.verify@")
            and st.status == "ok"
            and "citation_verified" in st.output_keys
            for st in step_traces
        )

        fts_app_id = str(app_cfg.retrieval_step_config.get("app_id", ""))
        if not fts_app_id:
            return ()

        top_k = int(app_cfg.retrieval_step_config.get("top_k", 3))
        ret_mode: Literal["any", "all"] = (
            "all"
            if app_cfg.retrieval_step_config.get("mode") == "all"
            else "any"
        )
        query_text = " ".join(str(v) for v in input_payload.values())
        hits = app_runtime._execute_lexical_retrieval(
            app_id=fts_app_id,
            query_text=query_text,
            top_k=top_k,
            mode=ret_mode,
        )

        cited_val = (
            str(output_payload.get(app_cfg.citation_field, "")).strip()
            if (cite_verify_step_ok and app_cfg.citation_field)
            else ""
        )

        refs: list[SourceReference] = []
        for h in hits:
            doc_id = str(h.get("doc_id", "doc"))
            asset_id, filename = cls._resolve_asset_provenance(doc_id, assets)
            passage_verified = False
            if cite_verify_step_ok and cited_val:
                try:
                    AppRuntime._verify_citation_against_retrieved(
                        cited_text=cited_val,
                        retrieved_docs=[h],
                        match_mode=app_cfg.citation_match_mode,
                        require_non_empty_retrieval=True,
                    )
                    passage_verified = True
                except Exception:
                    passage_verified = False

            refs.append(
                SourceReference(
                    doc_id=doc_id,
                    asset_id=asset_id,
                    filename=filename,
                    excerpt=str(h.get("content", ""))[:500],
                    score=float(h.get("score", 0.0) or 0.0),
                    citation_verified=passage_verified,
                    verified_citation=cited_val if passage_verified else None,
                )
            )
        return tuple(refs)

    @staticmethod
    def _format_assistant_display_text(
        output_payload: Mapping[str, Any],
        spec_outputs: Sequence[FieldSpec],
    ) -> str:
        if len(spec_outputs) == 1:
            only_key = spec_outputs[0].name
            if only_key in output_payload and isinstance(
                output_payload[only_key], str
            ):
                return output_payload[only_key]
        lines: list[str] = []
        for f in spec_outputs:
            if f.name in output_payload:
                val = output_payload[f.name]
                val_str = (
                    val
                    if isinstance(val, str)
                    else json.dumps(val, ensure_ascii=False)
                )
                lines.append(f"{f.name}: {val_str}")
        return "\n".join(lines) if lines else json.dumps(dict(output_payload))

    # ----------------------------------------------------------------------- #
    # 10-Step Chat Execution Pipeline
    # ----------------------------------------------------------------------- #
    def send_chat_message(
        self,
        app_id: str,
        session_id: str,
        *,
        owner_id: str = DEFAULT_RUNTIME_OWNER_ID,
        user_message: str,
        structured_inputs: Mapping[str, Any] | None = None,
    ) -> ChatTurnResponse:
        t0 = time.monotonic()

        # Step 1 & 2: Validate application ownership and ACTIVE lifecycle status
        inst = self.app_manager._get_authorized_instance(app_id, owner_id)
        if inst.state != RuntimeLifecycleState.ACTIVE:
            raise LifecycleStateError(
                f"Application '{inst.app_id}' is in state '{inst.state.value}'; must be ACTIVE to execute chat."
            )

        # Verify session belongs to (app_id, project_run_id, owner_id)
        _ = self.session_manager.get_session(
            app_id=inst.app_id,
            project_run_id=inst.project_run_id,
            session_id=session_id,
            owner_id=inst.owner_id,
        )

        # Step 3 & 4: Load application configuration and latest conversation history in chronological order
        app_cfg = inst.app_config
        manifest = inst.delivery_package.manifest
        prior_messages = self.session_manager.get_conversation_history(
            app_id=inst.app_id,
            project_run_id=inst.project_run_id,
            session_id=session_id,
            owner_id=inst.owner_id,
            limit=self.config.max_history_turns_in_prompt,
        )
        history_for_model = [
            {"role": m.role, "content": m.content} for m in prior_messages
        ]

        # Step 5: Deterministically resolve and validate inputs against the application's schema
        inputs_ok, input_payload, missing_fields, val_errors = (
            self._resolve_and_validate_inputs(
                app_cfg=app_cfg,
                user_message=user_message,
                structured_inputs=structured_inputs,
            )
        )
        if not inputs_ok:
            clarification_msg = (
                "Additional structured input is required before executing this application. "
                + (
                    f"Missing required field(s): {', '.join(missing_fields)}. "
                    if missing_fields
                    else ""
                )
                + (
                    f"Schema validation error(s): {'; '.join(val_errors)}"
                    if val_errors
                    else ""
                )
            ).strip()
            clarification_payload = {
                "status": "clarification_required",
                "missing_fields": list(missing_fields),
                "validation_errors": list(val_errors),
                "message": clarification_msg,
            }
            user_rec = self.session_manager.append_message(
                app_id=inst.app_id,
                project_run_id=inst.project_run_id,
                session_id=session_id,
                owner_id=inst.owner_id,
                role="user",
                content=user_message.strip() or json.dumps(dict(structured_inputs or {})),
                structured_payload=input_payload,
            )
            asst_rec = self.session_manager.append_message(
                app_id=inst.app_id,
                project_run_id=inst.project_run_id,
                session_id=session_id,
                owner_id=inst.owner_id,
                role="assistant",
                content=clarification_msg,
                structured_payload=clarification_payload,
            )
            return ChatTurnResponse(
                app_id=inst.app_id,
                session_id=session_id,
                status="clarification_required",
                user_message=user_rec,
                assistant_message=asst_rec,
                structured_output=clarification_payload,
                missing_fields=missing_fields,
                validation_errors=val_errors,
                source_references=(),
                wall_time_ms=max(1, int((time.monotonic() - t0) * 1000)),
            )

        # Step 6 & 7: Bind session-scoped Muse model port and execute the bundle workflow via AppRuntime
        wall_timeout_s = min(
            float(manifest.limits.wall_seconds),
            float(self.config.muse_request_timeout_seconds),
        )
        session_model_port = _SessionBoundModelPort(
            self.muse_client,
            app_id=inst.app_id,
            app_system_instructions=app_cfg.system_instructions,
            conversation_history=history_for_model,
            timeout_seconds=wall_timeout_s,
        )
        app_runtime = AppRuntime(
            inst.app_storage,
            inst.sandbox_verifier,
            session_model_port,
        )

        try:
            output_payload, exec_trace = app_runtime.execute_bundle(
                manifest,
                inst.bundle_files,
                input_payload,
                assets=inst.assets,
            )
        except MuseProviderError:
            raise
        except RuntimeExecutionError as exc:
            raise RuntimeServiceError(
                f"Application workflow execution failed: {exc}",
                code="workflow_execution_failed",
            ) from exc
        except Exception as exc:
            raise RuntimeServiceError(
                f"Unexpected runtime execution failure ({type(exc).__name__}).",
                code="workflow_execution_failed",
            ) from exc

        # Step 8: Validate structured output against the application's output schema
        out_errs = SandboxVerifier.validate_output_against_schema(
            output_payload, app_cfg.output_json_schema
        )
        if out_errs:
            raise RuntimeServiceError(
                f"Application output failed schema validation: {'; '.join(out_errs)}",
                code="output_schema_validation_failed",
            )

        # Step 9: Collect genuine source references & persist both conversation messages
        source_refs = self._collect_source_references(
            app_runtime=app_runtime,
            app_cfg=app_cfg,
            assets=inst.assets,
            input_payload=input_payload,
            output_payload=output_payload,
            step_traces=exec_trace.step_traces,
        )
        assistant_text = self._format_assistant_display_text(
            output_payload, app_cfg.spec_outputs
        )

        user_msg_record = self.session_manager.append_message(
            app_id=inst.app_id,
            project_run_id=inst.project_run_id,
            session_id=session_id,
            owner_id=inst.owner_id,
            role="user",
            content=user_message.strip() or json.dumps(input_payload),
            structured_payload=input_payload,
        )
        assistant_msg_record = self.session_manager.append_message(
            app_id=inst.app_id,
            project_run_id=inst.project_run_id,
            session_id=session_id,
            owner_id=inst.owner_id,
            role="assistant",
            content=assistant_text,
            structured_payload=output_payload,
            source_references=source_refs,
            step_traces=exec_trace.step_traces,
        )

        wall_ms = max(1, int((time.monotonic() - t0) * 1000))
        return ChatTurnResponse(
            app_id=inst.app_id,
            session_id=session_id,
            status="completed",
            user_message=user_msg_record,
            assistant_message=assistant_msg_record,
            structured_output=output_payload,
            source_references=source_refs,
            wall_time_ms=wall_ms,
        )

    async def asend_chat_message(
        self,
        app_id: str,
        session_id: str,
        *,
        owner_id: str = DEFAULT_RUNTIME_OWNER_ID,
        user_message: str,
        structured_inputs: Mapping[str, Any] | None = None,
    ) -> ChatTurnResponse:
        return await asyncio.to_thread(
            self.send_chat_message,
            app_id,
            session_id,
            owner_id=owner_id,
            user_message=user_message,
            structured_inputs=structured_inputs,
        )


# =========================================================================== #
# 8. COMPREHENSIVE SELF-TEST SUITE (Covers All 14 Required Regression Tests)
# =========================================================================== #


class _MockMuseTransport:
    """Deterministic transport stub for unit testing `MuseApiClient`."""

    def __init__(
        self,
        handler: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> None:
        self.handler = handler
        self.calls: list[dict[str, Any]] = []
        self.last_timeout: float | None = None

    def create_chat_completion(
        self,
        *,
        base_url: str,
        api_key: str,
        payload: dict[str, Any],
        timeout_seconds: float,
    ) -> dict[str, Any]:
        if not api_key:
            raise MuseAuthenticationError("Missing API key")
        self.calls.append(payload)
        self.last_timeout = timeout_seconds
        if self.handler is not None:
            content_obj = self.handler(payload)
        else:
            content_obj = {
                "decision": "approve_refund",
                "policy_citation": "Full refunds are granted within 30 calendar days of purchase",
            }
        return {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(content_obj),
                    }
                }
            ]
        }


def _build_test_signed_zip(
    *,
    signer: Ed25519Signer,
    verdict_status: Literal["ready", "not_ready"] = "ready",
    architecture: Literal["prompt_only", "retrieval", "tool_use"] = "retrieval",
    version_id: str = "v1.0.0-candidate",
    include_cite_verify: bool = True,
    multi_numeric_inputs: bool = False,
    tamper_file_bytes: bool = False,
    inject_traversal_path: str | None = None,
) -> tuple[bytes, Spec, SourceAssetInput]:
    inputs = [
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
    ]
    if multi_numeric_inputs:
        inputs.append(
            FieldSpec(
                name="order_id",
                data_type="integer",
                description="Numeric order identifier.",
                required=True,
            )
        )

    spec = Spec(
        goal="Triage customer refund requests against Section 4.2 Refund Policy and cite evidence.",
        inputs=inputs,
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
    in_props: dict[str, Any] = {
        "customer_query": {"type": "string"},
        "days_since_purchase": {"type": "integer"},
    }
    in_req = ["customer_query", "days_since_purchase"]
    if multi_numeric_inputs:
        in_props["order_id"] = {"type": "integer"}
        in_req.append("order_id")

    io_schema = {
        "inputs": {
            "type": "object",
            "required": in_req,
            "properties": in_props,
        },
        "outputs": {
            "type": "object",
            "required": ["decision", "policy_citation"],
            "properties": {
                "decision": {"type": "string"},
                "policy_citation": {"type": "string"},
            },
        },
    }

    app_id = f"app-{spec.content_hash()[:10]}"
    steps: list[dict[str, Any]] = [
        {
            "step_id": "s_in",
            "component_ref": "io.validate@1.0.0",
            "config": {"mode": "input"},
            "depends_on": [],
        },
    ]
    last_dep = "s_in"
    allowed_tools: list[str] = []

    if architecture in ("retrieval", "tool_use"):
        steps.append(
            {
                "step_id": "s_ingest",
                "component_ref": "doc.ingest@1.0.0",
                "config": {
                    "app_id": app_id,
                    "chunk_size": 400,
                    "overlap": 40,
                    "formats": ["md", "txt"],
                },
                "depends_on": [last_dep],
            }
        )
        steps.append(
            {
                "step_id": "s_ret",
                "component_ref": "retrieve.lexical@1.0.0",
                "config": {"app_id": app_id, "top_k": 3, "mode": "any"},
                "depends_on": ["s_ingest"],
            }
        )
        last_dep = "s_ret"

    if architecture == "tool_use":
        allowed_tools.append("fn.sla_check")
        steps.append(
            {
                "step_id": "s_fn",
                "component_ref": "fn.sandboxed@1.0.0",
                "config": {
                    "target_component_ref": "fn.sla_check@1.0.0",
                    "fn_config": {},
                },
                "depends_on": [last_dep],
            }
        )
        last_dep = "s_fn"

    steps.extend(
        [
            {
                "step_id": "s_prompt",
                "component_ref": "prompt.compose@1.0.0",
                "config": {
                    "template": "Goal: {goal}",
                    "verbatim_constraints": list(spec.constraints),
                    "max_context_tokens": 2000,
                },
                "depends_on": [last_dep],
            },
            {
                "step_id": "s_model",
                "component_ref": "model.chat@1.0.0",
                "config": {
                    "model": "muse-spark-1.3",
                    "effort": "low",
                    "max_tokens": 512,
                },
                "depends_on": ["s_prompt"],
            },
            {
                "step_id": "s_out",
                "component_ref": "output.structured@1.0.0",
                "config": {"json_schema": io_schema["outputs"]},
                "depends_on": ["s_model"],
            },
        ]
    )
    if architecture in ("retrieval", "tool_use") and include_cite_verify:
        steps.append(
            {
                "step_id": "s_cite",
                "component_ref": "cite.verify@1.0.0",
                "config": {
                    "citation_field": "policy_citation",
                    "match_mode": "substring",
                    "require_non_empty_retrieval": True,
                },
                "depends_on": ["s_out"],
            }
        )

    app_cfg = {
        "spec_hash": spec.content_hash(),
        "goal": spec.goal,
        "constraints": list(spec.constraints),
        "steps": steps,
    }
    files_data: dict[str, bytes] = {
        "app_config.json": _canonical_bytes(app_cfg),
        "schemas/io_schema.json": _canonical_bytes(io_schema),
        "prompts/system_prompt.txt": (
            f"Goal: {spec.goal}\n- Never approve refunds after 30 calendar days."
        ).encode("utf-8"),
    }
    if architecture == "tool_use":
        files_data["generated/fn.sla_check/1.0.0/fn.py"] = (
            "def run(input: dict, config: dict) -> dict:\n"
            "    days = int(input.get('days_since_purchase', 0))\n"
            "    return {'decision': 'approve_refund' if days <= 30 else 'reject_refund'}\n"
        ).encode("utf-8")

    af_list = tuple(
        ArtifactFile(path=p, sha256=sha256_hex(b), size_bytes=len(b))
        for p, b in sorted(files_data.items())
    )
    manifest = BundleManifest.seal(
        ArtifactContent(
            spec_hash=spec.content_hash(),
            architecture=architecture,
            runtime_model="muse-spark-1.3",
            reasoning_effort="low",
            entrypoint="app_config.json",
            files=af_list,
            allowed_tools=tuple(allowed_tools),
            limits=RuntimeLimits(wall_seconds=10, memory_mb=256),
        ),
        version_id=version_id,
        created_at=_now_utc(),
    )

    n_passed = 18 if verdict_status == "ready" else 2
    crit_results = tuple(
        CriterionResult.from_counts(
            criterion_id=c.criterion_id,
            threshold=c.min_pass_rate,
            n_passed=n_passed,
            n_cases=18,
        )
        for c in spec.acceptance_criteria
    )
    unsigned_verdict = Verdict(
        spec_hash=spec.content_hash(),
        artifact=manifest.ref,
        sealed_set_id="sealed_test_01",
        sealed_commitment_hash="a" * 64,
        status=verdict_status,
        criteria=crit_results,
        evidence_hash="b" * 64,
        issued_at=_now_utc(),
        signing_key_id=signer.key_id,
        signature="0" * 128,
    )
    sig_hex = signer.sign(unsigned_verdict.signing_payload())
    signed_verdict = unsigned_verdict.model_copy(update={"signature": sig_hex})

    pkg = DeliveryPackage(
        spec=spec,
        manifest=manifest,
        verdict=signed_verdict,
        repair_log=(),
        delivered_at=_now_utc(),
    )

    if tamper_file_bytes:
        files_data["prompts/system_prompt.txt"] += b"\nTAMPERED_AFTER_SEAL"

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(
        zip_buf, mode="w", compression=zipfile.ZIP_DEFLATED
    ) as zf:
        for rel_p, raw_b in sorted(files_data.items()):
            zf.writestr(rel_p, raw_b)
        zf.writestr(
            "delivery_package.json",
            _canonical_bytes(pkg.model_dump(mode="json")),
        )
        if inject_traversal_path:
            zf.writestr(inject_traversal_path, b"malicious")

    asset = SourceAssetInput(
        asset_id="pol_v1",
        filename="refund_policy.md",
        content=(
            "Section 4.2 Refund Policy: Full refunds are granted within 30 calendar days of purchase.\n\n"
            + ("Supplementary administrative note on enterprise billing. " * 20)
        ),
        format="md",
    )
    return zip_buf.getvalue(), spec, asset


class RuntimeServiceSelfTestSuite(unittest.TestCase):
    """Comprehensive 14-test regression suite for `backend/runtime_service.py`."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="adaptos_rt_svc_test_", ignore_cleanup_errors=True)
        self.tmp_path = Path(self._tmp.name)
        self.signer = Ed25519Signer(b"adaptos_runtime_svc_test_seed32!")
        self.cfg = RuntimeServiceConfig(
            runtime_data_root=self.tmp_path / "runtime_data",
            eval_public_key_bytes=self.signer.public_key_bytes,
            muse_api_key="test-muse-api-key-secret",
        )

    def tearDown(self) -> None:
        # Checkpoint SQLite WAL files before cleanup to release Windows file locks.
        import sqlite3 as _sqlite3
        for _db in self.tmp_path.rglob("*.db"):
            try:
                with _sqlite3.connect(str(_db), timeout=2.0) as _c:
                    _c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except Exception:
                pass
        self._tmp.cleanup()

    def test_01_path_traversal_rejection(self) -> None:
        """Test 1: Rejects path traversal in app_id, project_run_id, session_id, owner_id, and ZIP entries."""
        rt_svc = AdaptOSRuntimeService(
            self.cfg,
            muse_transport=_MockMuseTransport(),
            docker_runner_override=_simulated_docker_runner_for_tests,
        )
        valid_zip, _, asset = _build_test_signed_zip(signer=self.signer)

        for bad_id in ("../escape", "..\\escape", "/abs/path", "bad/id", "id with spaces", ""):
            with self.assertRaises(InvalidIdentifierError):
                rt_svc.provision_application(
                    valid_zip,
                    project_run_id="run_ok",
                    owner_id="user_1",
                    app_id=bad_id if bad_id else "../empty",
                    assets=[asset],
                )
            with self.assertRaises(InvalidIdentifierError):
                rt_svc.provision_application(
                    valid_zip,
                    project_run_id=bad_id,
                    owner_id="user_1",
                    app_id="app_ok",
                    assets=[asset],
                )

        bad_zip_traversal, _, _ = _build_test_signed_zip(
            signer=self.signer, inject_traversal_path="../../etc/passwd"
        )
        with self.assertRaises(PackageValidationError) as ctx_zip:
            rt_svc.provision_application(
                bad_zip_traversal,
                project_run_id="run_trav",
                owner_id="user_1",
                assets=[asset],
            )
        self.assertEqual(ctx_zip.exception.code, "unsafe_archive_path")

    def test_02_malformed_zip_rejection(self) -> None:
        """Test 2: Rejects empty bytes, non-ZIP data, and archives missing delivery_package.json."""
        rt_svc = AdaptOSRuntimeService(
            self.cfg,
            muse_transport=_MockMuseTransport(),
            docker_runner_override=_simulated_docker_runner_for_tests,
        )
        with self.assertRaises(PackageValidationError):
            rt_svc.provision_application(
                b"", project_run_id="run_empty", owner_id="user_1"
            )
        with self.assertRaises(PackageValidationError) as ctx_corrupt:
            rt_svc.provision_application(
                b"not-a-valid-zip-file",
                project_run_id="run_corrupt",
                owner_id="user_1",
            )
        self.assertEqual(ctx_corrupt.exception.code, "corrupted_archive")

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, mode="w") as zf:
            zf.writestr("app_config.json", b"{}")
        with self.assertRaises(PackageValidationError) as ctx_missing:
            rt_svc.provision_application(
                buf.getvalue(),
                project_run_id="run_missing_pkg",
                owner_id="user_1",
            )
        self.assertEqual(ctx_missing.exception.code, "missing_delivery_package")

    def test_03_zip_bomb_and_resource_limit_rejection(self) -> None:
        """Test 3: Rejects high-compression-ratio ZIP bombs, oversized archives, and excessive file counts."""
        strict_cfg = RuntimeServiceConfig(
            runtime_data_root=self.tmp_path / "strict_rt",
            eval_public_key_bytes=self.signer.public_key_bytes,
            muse_api_key="test-key",
            max_uncompressed_bytes=50_000,
            max_archive_files=5,
            max_compression_ratio=10.0,
        )
        rt_svc = AdaptOSRuntimeService(strict_cfg, muse_transport=_MockMuseTransport())

        # High compression ratio bomb (100 KB of zeroes compresses > 100:1)
        bomb_buf = io.BytesIO()
        with zipfile.ZipFile(
            bomb_buf, mode="w", compression=zipfile.ZIP_DEFLATED
        ) as zf:
            zf.writestr("bomb.txt", b"0" * 100_000)
        with self.assertRaises(PackageValidationError) as ctx_bomb:
            rt_svc.provision_application(
                bomb_buf.getvalue(),
                project_run_id="run_bomb",
                owner_id="user_1",
            )
        self.assertEqual(ctx_bomb.exception.code, "zip_bomb_detected")

        # Too many files in archive (> 5)
        many_buf = io.BytesIO()
        with zipfile.ZipFile(many_buf, mode="w") as zf:
            for i in range(7):
                zf.writestr(f"f_{i}.txt", b"hello")
        with self.assertRaises(PackageValidationError) as ctx_many:
            rt_svc.provision_application(
                many_buf.getvalue(),
                project_run_id="run_many",
                owner_id="user_1",
            )
        self.assertEqual(ctx_many.exception.code, "too_many_archive_files")

    def test_04_tampered_file_rejection(self) -> None:
        """Test 4: Rejects packages whose file bytes were modified after manifest sealing."""
        rt_svc = AdaptOSRuntimeService(
            self.cfg,
            muse_transport=_MockMuseTransport(),
            docker_runner_override=_simulated_docker_runner_for_tests,
        )
        bad_zip_tamper, _, asset = _build_test_signed_zip(
            signer=self.signer, tamper_file_bytes=True
        )
        with self.assertRaises(PackageValidationError) as ctx_tamper:
            rt_svc.provision_application(
                bad_zip_tamper,
                project_run_id="run_tamper",
                owner_id="user_1",
                assets=[asset],
            )
        self.assertEqual(ctx_tamper.exception.code, "bundle_integrity_failed")

    def test_05_invalid_verdict_signature_and_not_ready_rejection(self) -> None:
        """Test 5: Rejects forged Ed25519 Verdict signatures and not_ready Verdict packages."""
        rt_svc = AdaptOSRuntimeService(
            self.cfg,
            muse_transport=_MockMuseTransport(),
            docker_runner_override=_simulated_docker_runner_for_tests,
        )
        other_signer = Ed25519Signer(b"different_signer_private_seed32!")
        forged_zip, _, asset = _build_test_signed_zip(signer=other_signer)
        with self.assertRaises(PackageValidationError) as ctx_sig:
            rt_svc.provision_application(
                forged_zip,
                project_run_id="run_forged",
                owner_id="user_1",
                assets=[asset],
            )
        self.assertEqual(ctx_sig.exception.code, "verdict_signature_invalid")

        not_ready_zip, _, _ = _build_test_signed_zip(
            signer=self.signer, verdict_status="not_ready"
        )
        with self.assertRaises(PackageValidationError) as ctx_nr:
            rt_svc.provision_application(
                not_ready_zip,
                project_run_id="run_nr",
                owner_id="user_1",
                assets=[asset],
            )
        self.assertEqual(ctx_nr.exception.code, "verdict_not_ready")

    def test_06_safe_repeated_provisioning_preserves_storage_and_conversations(self) -> None:
        """Test 6: Repeated provisioning of the same or updated version never deletes existing
        conversations or wipes version-scoped storage.
        """
        rt_svc = AdaptOSRuntimeService(
            self.cfg,
            muse_transport=_MockMuseTransport(),
            docker_runner_override=_simulated_docker_runner_for_tests,
        )
        zip_v1, _, asset = _build_test_signed_zip(
            signer=self.signer, version_id="v1.0.0-candidate"
        )
        rt_svc.provision_application(
            zip_v1,
            project_run_id="run_safe_prov",
            owner_id="user_1",
            app_id="app_safe_prov",
            assets=[asset],
        )
        sess = rt_svc.create_chat_session(
            "app_safe_prov", owner_id="user_1", title="Preserved Session"
        )
        rt_svc.send_chat_message(
            "app_safe_prov",
            sess.session_id,
            owner_id="user_1",
            user_message="Refund request within 10 days",
        )

        # 6a. Idempotent re-provisioning of v1.0.0-candidate
        rt_svc.provision_application(
            zip_v1,
            project_run_id="run_safe_prov",
            owner_id="user_1",
            app_id="app_safe_prov",
            assets=[asset],
        )
        hist_after_idem = rt_svc.get_conversation_history(
            "app_safe_prov", sess.session_id, owner_id="user_1"
        )
        self.assertEqual(len(hist_after_idem), 2)

        # 6b. Upgrade to v2.0.0-candidate -> preserves existing session and history!
        zip_v2, _, _ = _build_test_signed_zip(
            signer=self.signer, version_id="v2.0.0-candidate"
        )
        summary_v2 = rt_svc.provision_application(
            zip_v2,
            project_run_id="run_safe_prov",
            owner_id="user_1",
            app_id="app_safe_prov",
            assets=[asset],
        )
        self.assertEqual(summary_v2.version_id, "v2.0.0-candidate")
        hist_after_upgrade = rt_svc.get_conversation_history(
            "app_safe_prov", sess.session_id, owner_id="user_1"
        )
        self.assertEqual(len(hist_after_upgrade), 2)

    def test_07_conversation_history_latest_n_chronological_ordering(self) -> None:
        """Test 7: Verifies that get_conversation_history(limit=K) returns the LATEST K messages
        in chronological (oldest-to-newest) order, and persists across service restarts.
        """
        rt_svc = AdaptOSRuntimeService(
            self.cfg,
            muse_transport=_MockMuseTransport(),
            docker_runner_override=_simulated_docker_runner_for_tests,
        )
        zip_v1, _, asset = _build_test_signed_zip(signer=self.signer)
        rt_svc.provision_application(
            zip_v1,
            project_run_id="run_hist",
            owner_id="user_1",
            app_id="app_hist",
            assets=[asset],
        )
        sess = rt_svc.create_chat_session("app_hist", owner_id="user_1")

        for idx in range(1, 7):
            rt_svc.session_manager.append_message(
                app_id="app_hist",
                project_run_id="run_hist",
                session_id=sess.session_id,
                owner_id="user_1",
                role="user" if idx % 2 == 1 else "assistant",
                content=f"msg_{idx}",
            )

        # Request latest 4 messages out of 6 -> must be [msg_3, msg_4, msg_5, msg_6] in chronological order!
        latest_four = rt_svc.get_conversation_history(
            "app_hist", sess.session_id, owner_id="user_1", limit=4
        )
        self.assertEqual(
            [m.content for m in latest_four],
            ["msg_3", "msg_4", "msg_5", "msg_6"],
        )

        # Simulate process restart by instantiating a new AdaptOSRuntimeService on the same directory
        rt_svc_restarted = AdaptOSRuntimeService(
            self.cfg,
            muse_transport=_MockMuseTransport(),
            docker_runner_override=_simulated_docker_runner_for_tests,
        )
        persisted_four = rt_svc_restarted.get_conversation_history(
            "app_hist", sess.session_id, owner_id="user_1", limit=4
        )
        self.assertEqual(
            [m.content for m in persisted_four],
            ["msg_3", "msg_4", "msg_5", "msg_6"],
        )

    def test_08_session_owner_and_single_owner_mode_isolation(self) -> None:
        """Test 8: Enforces application, project, session, and owner boundaries, including single-owner mode."""
        single_owner_cfg = RuntimeServiceConfig(
            runtime_data_root=self.tmp_path / "single_owner_rt",
            eval_public_key_bytes=self.signer.public_key_bytes,
            muse_api_key="test-key",
            default_owner_id="default_owner",
            enforce_single_owner_mode=True,
        )
        rt_svc = AdaptOSRuntimeService(
            single_owner_cfg,
            muse_transport=_MockMuseTransport(),
            docker_runner_override=_simulated_docker_runner_for_tests,
        )
        zip_v1, _, asset = _build_test_signed_zip(signer=self.signer)

        # Arbitrary untrusted frontend owner_id rejected in single-owner mode
        with self.assertRaises(RuntimeAuthorizationError):
            rt_svc.provision_application(
                zip_v1,
                project_run_id="run_iso_1",
                owner_id="spoofed_frontend_user",
                app_id="app_iso_1",
                assets=[asset],
            )

        rt_svc.provision_application(
            zip_v1,
            project_run_id="run_iso_1",
            app_id="app_iso_1",
            assets=[asset],
        )
        rt_svc.provision_application(
            zip_v1,
            project_run_id="run_iso_2",
            app_id="app_iso_2",
            assets=[asset],
        )
        sess_app1 = rt_svc.create_chat_session("app_iso_1")

        # Accessing app_iso_1's session through app_iso_2 is rejected
        with self.assertRaises(RuntimeAuthorizationError):
            rt_svc.get_conversation_history("app_iso_2", sess_app1.session_id)

    def test_09_numeric_input_validation_and_clarification_response(self) -> None:
        """Test 9: Never assigns a bare number to multiple numeric fields; returns structured
        clarification_required when required inputs are ambiguous or missing, and executes when unambiguous.
        """
        mock_muse = _MockMuseTransport()
        rt_svc = AdaptOSRuntimeService(
            self.cfg,
            muse_transport=mock_muse,
            docker_runner_override=_simulated_docker_runner_for_tests,
        )
        # Bundle with TWO required integer fields: days_since_purchase and order_id
        multi_num_zip, _, asset = _build_test_signed_zip(
            signer=self.signer, multi_numeric_inputs=True
        )
        rt_svc.provision_application(
            multi_num_zip,
            project_run_id="run_num_val",
            owner_id="user_1",
            app_id="app_num_val",
            assets=[asset],
        )
        sess = rt_svc.create_chat_session("app_num_val", owner_id="user_1")

        # 9a. Ambiguous message with bare number '12' -> must NOT assign '12' to both fields!
        turn_clarify = rt_svc.send_chat_message(
            "app_num_val",
            sess.session_id,
            owner_id="user_1",
            user_message="Please refund my order from 12 days ago.",
        )
        self.assertEqual(turn_clarify.status, "clarification_required")
        self.assertIn("days_since_purchase", turn_clarify.missing_fields)
        self.assertIn("order_id", turn_clarify.missing_fields)
        self.assertEqual(len(mock_muse.calls), 0)

        # 9b. Explicit labeled fields in message -> resolves deterministically and executes!
        turn_ok = rt_svc.send_chat_message(
            "app_num_val",
            sess.session_id,
            owner_id="user_1",
            user_message="Refund request: days_since_purchase: 12, order_id: 5001",
        )
        self.assertEqual(turn_ok.status, "completed")
        self.assertEqual(turn_ok.user_message.structured_payload["days_since_purchase"], 12)
        self.assertEqual(turn_ok.user_message.structured_payload["order_id"], 5001)
        self.assertEqual(len(mock_muse.calls), 1)

    def test_10_runtime_lifecycle_transitions_and_active_gate(self) -> None:
        """Test 10: Verifies VERIFIED -> PROVISIONING -> READY -> ACTIVE -> STOPPED -> DEACTIVATED
        and rejects invalid state transitions.
        """
        rt_svc = AdaptOSRuntimeService(
            self.cfg,
            muse_transport=_MockMuseTransport(),
            docker_runner_override=_simulated_docker_runner_for_tests,
        )
        valid_zip, _, asset = _build_test_signed_zip(signer=self.signer)

        summary = rt_svc.provision_application(
            valid_zip,
            project_run_id="run_life",
            owner_id="user_1",
            app_id="app_life",
            assets=[asset],
            auto_activate=False,
        )
        self.assertEqual(summary.state, RuntimeLifecycleState.READY)

        # Cannot stop an application that is in READY (not ACTIVE)
        with self.assertRaises(LifecycleStateError):
            rt_svc.stop_application("app_life", owner_id="user_1")

        sess = rt_svc.create_chat_session("app_life", owner_id="user_1")
        with self.assertRaises(LifecycleStateError):
            rt_svc.send_chat_message(
                "app_life",
                sess.session_id,
                owner_id="user_1",
                user_message="Refund order from 10 days ago",
            )

        summary = rt_svc.activate_application("app_life", owner_id="user_1")
        self.assertEqual(summary.state, RuntimeLifecycleState.ACTIVE)

        summary = rt_svc.stop_application("app_life", owner_id="user_1")
        self.assertEqual(summary.state, RuntimeLifecycleState.STOPPED)

        summary = rt_svc.deactivate_application("app_life", owner_id="user_1")
        self.assertEqual(summary.state, RuntimeLifecycleState.DEACTIVATED)

        # Cannot activate directly from DEACTIVATED without recover_application()
        with self.assertRaises(LifecycleStateError):
            rt_svc.activate_application("app_life", owner_id="user_1")

    def test_11_crash_recovery_from_interrupted_provisioning(self) -> None:
        """Test 11: Applications left in PROVISIONING after an unexpected crash can be recovered
        safely, and recovery refuses to activate tampered packages.
        """
        rt_svc = AdaptOSRuntimeService(
            self.cfg,
            muse_transport=_MockMuseTransport(),
            docker_runner_override=_simulated_docker_runner_for_tests,
        )
        valid_zip, _, asset = _build_test_signed_zip(signer=self.signer)
        rt_svc.provision_application(
            valid_zip,
            project_run_id="run_crash",
            owner_id="user_1",
            app_id="app_crash",
            assets=[asset],
        )

        # Simulate process crash mid-provisioning by setting state='PROVISIONING' in SQLite
        with sqlite3.connect(rt_svc.app_manager.db_path) as conn:
            conn.execute(
                "UPDATE runtime_applications SET state='PROVISIONING', error_code=NULL WHERE app_id='app_crash'"
            )

        # Reload manager from disk
        rt_svc_reloaded = AdaptOSRuntimeService(
            self.cfg,
            muse_transport=_MockMuseTransport(),
            docker_runner_override=_simulated_docker_runner_for_tests,
        )
        st_interrupted = rt_svc_reloaded.get_application_status(
            "app_crash", owner_id="user_1"
        )
        self.assertEqual(st_interrupted.state, RuntimeLifecycleState.PROVISIONING)
        self.assertEqual(st_interrupted.error_code, "interrupted_provisioning")

        # 11a. Recover valid interrupted application -> succeeds and reaches ACTIVE
        recovered = rt_svc_reloaded.recover_application(
            "app_crash", owner_id="user_1", auto_activate=True
        )
        self.assertEqual(recovered.state, RuntimeLifecycleState.ACTIVE)

        # 11b. Tamper with persisted bundle_files in memory/DB and attempt recovery -> fails closed into FAILED!
        inst = rt_svc_reloaded.app_manager._instances["app_crash"]
        inst.state = RuntimeLifecycleState.PROVISIONING
        inst.bundle_files["prompts/system_prompt.txt"] = b"CORRUPTED_BYTES"
        with self.assertRaises(PackageValidationError):
            rt_svc_reloaded.recover_application(
                "app_crash", owner_id="user_1", auto_activate=True
            )
        self.assertEqual(
            rt_svc_reloaded.get_application_status("app_crash", owner_id="user_1").state,
            RuntimeLifecycleState.FAILED,
        )

    def test_12_citation_verification_and_provenance_preservation(self) -> None:
        """Test 12: Only marks citations as verified when cite.verify ran and confirmed the specific
        passage, and preserves asset_id and filename provenance.
        """
        mock_muse = _MockMuseTransport()
        rt_svc = AdaptOSRuntimeService(
            self.cfg,
            muse_transport=mock_muse,
            docker_runner_override=_simulated_docker_runner_for_tests,
        )

        # 12a. Bundle WITH cite.verify step
        zip_with_cite, _, asset = _build_test_signed_zip(
            signer=self.signer, include_cite_verify=True
        )
        rt_svc.provision_application(
            zip_with_cite,
            project_run_id="run_cite_yes",
            owner_id="user_1",
            app_id="app_cite_yes",
            assets=[asset],
        )
        s1 = rt_svc.create_chat_session("app_cite_yes", owner_id="user_1")
        turn_yes = rt_svc.send_chat_message(
            "app_cite_yes",
            s1.session_id,
            owner_id="user_1",
            user_message="Refund my purchase from 10 days ago under Section 4.2.",
        )
        self.assertTrue(len(turn_yes.source_references) >= 1)
        matching_refs = [
            sr for sr in turn_yes.source_references if sr.citation_verified
        ]
        self.assertEqual(len(matching_refs), 1)
        self.assertEqual(matching_refs[0].asset_id, "pol_v1")
        self.assertEqual(matching_refs[0].filename, "refund_policy.md")
        self.assertIsNotNone(matching_refs[0].verified_citation)

        # 12b. Bundle WITHOUT cite.verify step -> citation_verified must be False and verified_citation None!
        zip_no_cite, _, _ = _build_test_signed_zip(
            signer=self.signer, include_cite_verify=False
        )
        rt_svc.provision_application(
            zip_no_cite,
            project_run_id="run_cite_no",
            owner_id="user_1",
            app_id="app_cite_no",
            assets=[asset],
        )
        s2 = rt_svc.create_chat_session("app_cite_no", owner_id="user_1")
        turn_no = rt_svc.send_chat_message(
            "app_cite_no",
            s2.session_id,
            owner_id="user_1",
            user_message="Refund my purchase from 10 days ago under Section 4.2.",
        )
        self.assertTrue(
            all(
                not sr.citation_verified and sr.verified_citation is None
                for sr in turn_no.source_references
            )
        )

    def test_13_muse_request_formatting_json_schema_and_max_completion_tokens(self) -> None:
        """Test 13: Verifies MuseApiClient formats requests with response_format.type='json_schema',
        response_format.json_schema={name, schema, strict}, and max_completion_tokens.
        """
        mock_transport = _MockMuseTransport()
        client = MuseApiClient(self.cfg, transport=mock_transport)
        schema = {
            "type": "object",
            "required": ["decision"],
            "properties": {"decision": {"type": "string"}},
        }
        res = client.complete_json(
            system_prompt="System instructions",
            user_prompt="User prompt",
            output_schema=schema,
            model_id="muse-spark-1.3",
            effort="low",
            max_tokens=512,
            schema_name="refund_triage_schema",
            conversation_history=[
                {"role": "user", "content": "Prior question"},
                {"role": "assistant", "content": "Prior answer"},
            ],
        )
        self.assertEqual(res["decision"], "approve_refund")
        self.assertEqual(len(mock_transport.calls), 1)
        sent = mock_transport.calls[0]
        self.assertEqual(sent["max_completion_tokens"], 512)
        self.assertNotIn("max_tokens", sent)
        self.assertEqual(sent["response_format"]["type"], "json_schema")
        self.assertEqual(
            sent["response_format"]["json_schema"]["name"],
            "refund_triage_schema",
        )
        self.assertEqual(
            sent["response_format"]["json_schema"]["schema"], schema
        )
        self.assertEqual(
            [m["role"] for m in sent["messages"]],
            ["system", "user", "assistant", "user"],
        )

    def test_14_muse_timeout_and_provider_error_handling(self) -> None:
        """Test 14: Verifies MuseApiClient handling of timeouts, HTTP 401/403, HTTP 429, and malformed JSON."""
        class _FailingTransport:
            def __init__(self, mode: str) -> None:
                self.mode = mode

            def create_chat_completion(self, **kwargs: Any) -> dict[str, Any]:
                if self.mode == "timeout":
                    raise MuseProviderTimeoutError("Timed out")
                if self.mode == "auth":
                    raise MuseAuthenticationError("401 Unauthorized")
                if self.mode == "rate":
                    raise MuseRateLimitError("429 Too Many Requests")
                return {
                    "choices": [
                        {"message": {"role": "assistant", "content": "{malformed_json"}}
                    ]
                }

        for mode, expected_exc in (
            ("timeout", MuseProviderTimeoutError),
            ("auth", MuseAuthenticationError),
            ("rate", MuseRateLimitError),
            ("malformed", MuseProviderError),
        ):
            client = MuseApiClient(self.cfg, transport=_FailingTransport(mode))
            with self.assertRaises(expected_exc):
                client.complete_json(
                    system_prompt="s",
                    user_prompt="u",
                    output_schema={"type": "object"},
                    model_id="muse-spark-1.3",
                    effort="low",
                    max_tokens=128,
                )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="AdaptOS Generic MVP Runtime Service"
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run built-in 14-test Runtime Service unittest suite",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(
            RuntimeServiceSelfTestSuite
        )
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        return 0 if result.wasSuccessful() else 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())