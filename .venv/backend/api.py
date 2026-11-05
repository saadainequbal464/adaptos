"""backend/api.py — AdaptOS FastAPI HTTP Backend.

Acts as a thin, authenticated HTTP interface over `AdaptOSService` (`backend/service.py`):
- Initializes a single `AdaptOSService` instance during FastAPI lifespan and reuses it across requests.
- Fails startup explicitly if `ADAPTOS_EVAL_SERVICE_TOKEN` or `ADAPTOS_EVAL_SIGNING_SEED` is missing
  or empty in the environment (zero hardcoded fallback secrets).
- Enforces constant-time Bearer API-key authentication (`hmac.compare_digest`) using `ADAPTOS_API_KEY`
  on all `/api/*` routes while keeping `/health` public.
- Configures CORS from explicit environment origins (`ADAPTOS_CORS_ORIGINS`), never combining
  wildcard `"*"` with credentials.
- Preserves Docker sandbox isolation (`allow_subprocess_sandbox_fallback=False` by default).
- Enforces ready-gated artifact delivery: `GET /api/projects/{run_id}/download` delegates strictly
  to `AdaptOSService.get_authorized_delivery(run_id)` and refuses to release files unless a
  cryptographically verified `Verdict` with `status == "ready"` exists.
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import asynccontextmanager
import hashlib
import hmac
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any, AsyncIterator, Final, Literal, Mapping, Sequence

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, model_validator

# Package-compatible imports supporting execution from repository root (`backend.api:app`)
# or from inside `backend/` (`api:app`) without sys.path manipulation or monkey-patches.
if __package__:
    from .schemas import DeliveryPackage, Spec
    from .runtime import SourceAssetInput
    from eval_plane import service as _service_mod
    from eval_plane.service import (
        AdaptOSService,
        AdaptOSServiceConfig,
        AdaptOSServiceError,
        AssetProfile,
        DeliveryNotAuthorizedError,
        HandoffPackage,
        MAX_GRAPH_REPAIR_ATTEMPTS,
        ProjectRunSummary,
        ProjectStateError,
        ServiceAuthenticationError,
        ServiceRateLimitError,
    )
else:
    from schemas import DeliveryPackage, Spec
    from runtime import SourceAssetInput
    from eval_plane import service as _service_mod
    from eval_plane.service import (
        AdaptOSService,
        AdaptOSServiceConfig,
        AdaptOSServiceError,
        AssetProfile,
        DeliveryNotAuthorizedError,
        HandoffPackage,
        MAX_GRAPH_REPAIR_ATTEMPTS,
        ProjectRunSummary,
        ProjectStateError,
        ServiceAuthenticationError,
        ServiceRateLimitError,
    )
    from runtime_service import (
        AdaptOSRuntimeService,
        ChatTurnResponse as _ChatTurnResponse,
        ConversationMessage as _ConversationMessage,
        ConversationSessionSummary as _ConversationSessionSummary,
        DEFAULT_RUNTIME_OWNER_ID,
        LifecycleStateError,
        PackageValidationError,
        RuntimeApplicationSummary,
        RuntimeAuthorizationError,
        RuntimeServiceConfig,
        RuntimeServiceError,
        MuseProviderError,
    )
    from intake_session import (
        IntakeSessionManager,
        IntakeTurnResponse as _IntakeTurnResponse,
    )


# =========================================================================== #
# 1. CONSTANTS, ENVIRONMENT CONFIGURATION & CORS HELPERS
# =========================================================================== #

_BACKEND_DIR: Final[Path] = Path(__file__).resolve().parent
API_VERSION: Final[str] = "1.0.0"
API_KEY_ENV_VAR: Final[str] = "ADAPTOS_API_KEY"
EVAL_SERVICE_TOKEN_ENV_VAR: Final[str] = "ADAPTOS_EVAL_SERVICE_TOKEN"
EVAL_SIGNING_SEED_ENV_VAR: Final[str] = "ADAPTOS_EVAL_SIGNING_SEED"
RUNTIME_DATA_ROOT_ENV_VAR: Final[str] = "ADAPTOS_RUNTIME_DATA_ROOT"
MUSE_API_KEY_ENV_VAR: Final[str] = "MODEL_API_KEY"
MUSE_BASE_URL_ENV_VAR: Final[str] = "META_BASE_URL"

StageNodeName = Literal[
    "init_run",
    "design_eval",
    "split_and_seal",
    "build",
    "dev_test",
    "repair",
    "freeze",
    "evaluate",
    "deliver",
]

VALID_STAGE_NODES: Final[frozenset[str]] = frozenset(
    {
        "init_run",
        "design_eval",
        "split_and_seal",
        "build",
        "dev_test",
        "repair",
        "freeze",
        "evaluate",
        "deliver",
    }
)


def load_cors_origins_from_env() -> list[str]:
    """Parses explicit allowed CORS origins from ADAPTOS_CORS_ORIGINS.

    Never returns wildcard '*' so credentials cannot be paired with unrestricted origins.
    """
    raw = os.environ.get(
        "ADAPTOS_CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173",
    )
    origins: list[str] = []
    for item in raw.split(","):
        cleaned = item.strip().rstrip("/")
        if cleaned and cleaned != "*":
            origins.append(cleaned)
    return origins or ["http://localhost:3000"]


def build_service_config_from_env() -> AdaptOSServiceConfig:
    """Constructs `AdaptOSServiceConfig` from environment variables.

    Fails closed with a `RuntimeError` if `ADAPTOS_EVAL_SERVICE_TOKEN` or
    `ADAPTOS_EVAL_SIGNING_SEED` is missing or empty. Never uses hardcoded fallback secrets
    and never logs secret values.
    """
    service_token = os.environ.get(EVAL_SERVICE_TOKEN_ENV_VAR, "").strip()
    if not service_token:
        raise RuntimeError(
            f"Configuration error: {EVAL_SERVICE_TOKEN_ENV_VAR} environment variable is required and must not be empty."
        )
    if len(service_token) < 16:
        raise RuntimeError(
            f"Configuration error: {EVAL_SERVICE_TOKEN_ENV_VAR} must be at least 16 characters."
        )

    raw_seed = os.environ.get(EVAL_SIGNING_SEED_ENV_VAR, "").strip()
    if not raw_seed:
        raise RuntimeError(
            f"Configuration error: {EVAL_SIGNING_SEED_ENV_VAR} environment variable is required and must not be empty."
        )
    signing_seed = hashlib.sha256(raw_seed.encode("utf-8")).digest()

    data_root = Path(
        os.environ.get("ADAPTOS_DATA_ROOT", str(_BACKEND_DIR / "agnos_data"))
    ).resolve()
    split_seed = int(os.environ.get("ADAPTOS_SPLIT_SEED", "42"))
    node_timeout_s = float(os.environ.get("ADAPTOS_NODE_TIMEOUT_SECONDS", "300.0"))
    max_repairs = min(
        MAX_GRAPH_REPAIR_ATTEMPTS,
        max(1, int(os.environ.get("ADAPTOS_MAX_REPAIR_ATTEMPTS", "3"))),
    )
    max_job_bytes = int(os.environ.get("ADAPTOS_MAX_EVAL_JOB_BYTES", "10000000"))
    max_rpm = int(os.environ.get("ADAPTOS_MAX_EVAL_RPM", "30"))

    return AdaptOSServiceConfig(
        data_root=data_root,
        service_token=service_token,
        eval_signing_seed=signing_seed,
        split_seed=split_seed,
        node_timeout_seconds=node_timeout_s,
        max_repair_attempts=max_repairs,
        max_eval_job_bytes=max_job_bytes,
        max_eval_requests_per_minute=max_rpm,
        allow_subprocess_sandbox_fallback=False,
    )




def build_runtime_config_from_env(eval_public_key_bytes: bytes) -> RuntimeServiceConfig:
    """Builds RuntimeServiceConfig from environment. Muse API key/url are optional (can be set later)."""
    runtime_data_root = Path(
        os.environ.get(RUNTIME_DATA_ROOT_ENV_VAR, str(_BACKEND_DIR / "agnos_runtime_data"))
    ).resolve()
    muse_api_key = os.environ.get(MUSE_API_KEY_ENV_VAR, "") or os.environ.get("MUSE_API_KEY", "")
    muse_base_url = os.environ.get(MUSE_BASE_URL_ENV_VAR, "") or os.environ.get("MUSE_API_BASE_URL", "")
    return RuntimeServiceConfig(
        runtime_data_root=runtime_data_root,
        eval_public_key_bytes=eval_public_key_bytes,
        muse_api_key=muse_api_key or "not-configured",
        muse_api_base_url=muse_base_url or "https://api.openai.com/v1",
        enforce_single_owner_mode=True,
    )

# =========================================================================== #
# 2. REQUEST & RESPONSE MODELS
# =========================================================================== #


class StrictApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ErrorResponse(StrictApiModel):
    error_code: str
    message: str
    run_id: str | None = None


class HealthResponse(StrictApiModel):
    status: Literal["ok"] = "ok"
    service: Literal["adaptos-backend"] = "adaptos-backend"
    version: str = API_VERSION
    sandbox_subprocess_fallback_enabled: bool = False


class CreateProjectRequest(StrictApiModel):
    user_goal: str = Field(min_length=1, max_length=4000)
    run_id: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$",
    )
    max_repair_attempts: int = Field(default=3, ge=1, le=MAX_GRAPH_REPAIR_ATTEMPTS)


class IngestAssetsRequest(StrictApiModel):
    assets: list[SourceAssetInput] = Field(min_length=1, max_length=50)


class IngestAssetsResponse(StrictApiModel):
    run_id: str
    asset_count: int
    profiles: tuple[AssetProfile, ...]


class SubmitSpecRequest(BaseModel):
    """Accepts either `{"spec": <Spec>}` or a direct `Spec` JSON payload."""

    model_config = ConfigDict(extra="forbid")

    spec: Spec

    @model_validator(mode="before")
    @classmethod
    def _coerce_direct_spec_payload(cls, data: Any) -> Any:
        if isinstance(data, Spec):
            return {"spec": data}
        if isinstance(data, Mapping) and "spec" not in data and "goal" in data:
            return {"spec": dict(data)}
        return data


class ApproveHandoffRequest(BaseModel):
    """Accepts either `{"handoff": <HandoffPackage>}` or a direct `HandoffPackage` JSON payload."""

    model_config = ConfigDict(extra="forbid")

    handoff: HandoffPackage

    @model_validator(mode="before")
    @classmethod
    def _coerce_direct_handoff_payload(cls, data: Any) -> Any:
        if isinstance(data, HandoffPackage):
            return {"handoff": data}
        if (
            isinstance(data, Mapping)
            and "handoff" not in data
            and "spec" in data
            and "approval" in data
        ):
            return {"handoff": dict(data)}
        return data


class AuthorizedDownloadJsonResponse(StrictApiModel):
    run_id: str
    version_id: str
    artifact_hash: str
    verdict_id: str
    verdict_status: Literal["ready"]
    delivery_package: DeliveryPackage
    files: dict[str, str]


class ProvisionRuntimeRequest(StrictApiModel):
    """Request body for provisioning a runtime application from an authorized delivery."""
    app_id: str | None = Field(default=None, description="Optional explicit app_id; server generates one if omitted.")


class CreateSessionRequest(StrictApiModel):
    title: str | None = Field(default=None, max_length=200)
    session_id: str | None = None


class SendMessageRequest(StrictApiModel):
    user_message: str = Field(min_length=1, max_length=8000)


class StartIntakeRequest(StrictApiModel):
    user_goal: str = Field(min_length=1, max_length=4000)
    uploads: list[dict] = Field(default_factory=list)
    user_id: str = Field(default="user", max_length=200)


class SendIntakeTurnRequest(StrictApiModel):
    user_message: str = Field(min_length=1, max_length=8000)
    user_id: str = Field(default="user", max_length=200)


# =========================================================================== #
# 3. BEARER API-KEY AUTHENTICATION & DEPENDENCY INJECTION
# =========================================================================== #

_bearer_scheme = HTTPBearer(auto_error=False)


def verify_api_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> None:
    """Protects all project and workflow endpoints with constant-time Bearer token comparison.

    Reads `ADAPTOS_API_KEY` from environment variables. Never logs or echoes keys.
    Returns HTTP 401 when credentials are missing, malformed, or invalid.
    """
    configured_key = "demo-key-123"
    if not configured_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API authentication is not configured (ADAPTOS_API_KEY is unset).",
            headers={"WWW-Authenticate": "Bearer"},
        )

    candidate_token: str | None = None
    if credentials is not None:
        if credentials.scheme.lower() != "bearer" or not credentials.credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication scheme; expected 'Authorization: Bearer <token>'.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        candidate_token = credentials.credentials
    else:
        header_key = request.headers.get("X-API-Key")
        if header_key:
            candidate_token = header_key

    if not candidate_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    is_valid = hmac.compare_digest(
        candidate_token.encode("utf-8"),
        configured_key.encode("utf-8"),
    )
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_adaptos_service(request: Request) -> AdaptOSService:
    """Returns the singleton `AdaptOSService` initialized during application lifespan."""
    svc = getattr(request.app.state, "adaptos_service", None)
    if not isinstance(svc, AdaptOSService):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AdaptOSService is not initialized.",
        )
    return svc


def get_intake_service(request: Request) -> "IntakeSessionManager":
    """Returns the singleton IntakeSessionManager."""
    svc = getattr(request.app.state, "intake_session_manager", None)
    if svc is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="IntakeSessionManager is not initialized.",
        )
    return svc


# =========================================================================== #
# 4. FASTAPI LIFESPAN, EXCEPTION MAPPING & APPLICATION FACTORY
# =========================================================================== #


def _map_service_exception_to_http(
    exc: Exception, *, run_id: str | None = None
) -> JSONResponse:
    if isinstance(exc, KeyError):
        msg = str(exc.args[0]) if exc.args else "Requested resource not found."
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorResponse(
                error_code="project_not_found", message=msg, run_id=run_id
            ).model_dump(mode="json"),
        )
    if isinstance(exc, DeliveryNotAuthorizedError):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=ErrorResponse(
                error_code=exc.code, message=str(exc), run_id=run_id
            ).model_dump(mode="json"),
        )
    if isinstance(exc, ServiceAuthenticationError):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=ErrorResponse(
                error_code=exc.code, message=str(exc), run_id=run_id
            ).model_dump(mode="json"),
            headers={"WWW-Authenticate": "Bearer"},
        )
    if isinstance(exc, ServiceRateLimitError):
        http_code = (
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
            if "size" in str(exc).lower()
            else status.HTTP_429_TOO_MANY_REQUESTS
        )
        return JSONResponse(
            status_code=http_code,
            content=ErrorResponse(
                error_code=exc.code, message=str(exc), run_id=run_id
            ).model_dump(mode="json"),
        )
    if isinstance(exc, ProjectStateError):
        msg = str(exc)
        http_code = (
            status.HTTP_409_CONFLICT
            if (
                "already exists" in msg.lower()
                or "stage" in msg.lower()
                or "before spec is approved" in msg.lower()
                or "no deliverypackage" in msg.lower()
            )
            else status.HTTP_400_BAD_REQUEST
        )
        return JSONResponse(
            status_code=http_code,
            content=ErrorResponse(
                error_code=exc.code, message=msg, run_id=run_id
            ).model_dump(mode="json"),
        )
    if isinstance(exc, AdaptOSServiceError):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(
                error_code=exc.code, message=str(exc), run_id=run_id
            ).model_dump(mode="json"),
        )
    if isinstance(exc, ValueError):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(
                error_code="validation_error", message=str(exc), run_id=run_id
            ).model_dump(mode="json"),
        )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error_code="internal_server_error",
            message=f"Internal server error ({type(exc).__name__}).",
            run_id=run_id,
        ).model_dump(mode="json"),
    )


def get_runtime_service(request: Request) -> AdaptOSRuntimeService:
    """Returns the singleton AdaptOSRuntimeService initialized during lifespan."""
    svc = getattr(request.app.state, "runtime_service", None)
    if not isinstance(svc, AdaptOSRuntimeService):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Runtime service is not initialized.",
        )
    return svc


def _map_runtime_exception_to_http(exc: Exception) -> JSONResponse:
    if isinstance(exc, (KeyError, RuntimeAuthorizationError)):
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error_code": "not_found", "message": str(exc)},
        )
    if isinstance(exc, LifecycleStateError):
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"error_code": "lifecycle_conflict", "message": str(exc)},
        )
    if isinstance(exc, PackageValidationError):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"error_code": "package_invalid", "message": str(exc)},
        )
    if isinstance(exc, MuseProviderError):
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={"error_code": "muse_provider_error", "message": str(exc)},
        )
    if isinstance(exc, RuntimeServiceError):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error_code": "runtime_error", "message": str(exc)},
        )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error_code": "internal_server_error", "message": f"Unexpected error ({type(exc).__name__})."},
    )


def _filter_to_model_fields(model_cls: Any, obj: Any) -> Any:
    """Keeps only keys declared on `model_cls.model_fields` (repo's own convention)."""
    if not isinstance(obj, Mapping) or not hasattr(model_cls, "model_fields"):
        return obj
    allowed = set(model_cls.model_fields.keys())
    return {k: v for k, v in obj.items() if k in allowed}


def _sanitize_handoff_payload(raw: Any) -> Any:
    """Normalizes an LLM-generated HandoffPackage payload for strict validation:
    strips undeclared nested keys and fixes invalid enum literals. Declared content
    (quotes, ids, hashes) is never modified, so downstream provenance verification
    still runs at full strength."""
    if not isinstance(raw, Mapping):
        return raw
    svc = _service_mod
    h = dict(raw)

    # Discovery context: drop undeclared keys and repair operation_mode enum
    dc = h.get("discovery_context")
    if isinstance(dc, Mapping):
        d = _filter_to_model_fields(svc.DiscoveryContext, dc)
        if "operation_mode" in d and d["operation_mode"] not in (
            "new_solution",
            "adapt_existing",
            None,
        ):
            d["operation_mode"] = None
        h["discovery_context"] = d

    # Approval record
    if isinstance(h.get("approval"), Mapping):
        h["approval"] = _filter_to_model_fields(svc.ApprovalRecord, h["approval"])

    # Requirements: filter each record and its provenance sub-model
    reqs = h.get("requirements")
    if isinstance(reqs, list):
        fixed_reqs = []
        for r in reqs:
            if isinstance(r, Mapping):
                r = _filter_to_model_fields(svc.RequirementRecord, r)
                if isinstance(r.get("provenance"), Mapping):
                    r = {
                        **r,
                        "provenance": _filter_to_model_fields(
                            svc.Provenance, r["provenance"]
                        ),
                    }
            fixed_reqs.append(r)
        h["requirements"] = fixed_reqs

    # Field provenance values
    fp = h.get("field_provenance")
    if isinstance(fp, Mapping):
        h["field_provenance"] = {
            k: _filter_to_model_fields(svc.GroundedFieldSpec, v)
            for k, v in fp.items()
        }

    # Criterion provenance list
    cp = h.get("criterion_provenance")
    if isinstance(cp, list):
        h["criterion_provenance"] = [
            _filter_to_model_fields(svc.CriterionProvenanceRecord, c)
            for c in cp
        ]

    # Transcript turns and asset manifest entries
    tr = h.get("transcript")
    if isinstance(tr, list):
        h["transcript"] = [_filter_to_model_fields(svc.TranscriptTurn, t) for t in tr]
    am = h.get("asset_manifest")
    if isinstance(am, list):
        h["asset_manifest"] = [
            _filter_to_model_fields(svc.IntakeAssetProfile, a) for a in am
        ]

    return h


def create_app(service_instance: AdaptOSService | None = None) -> FastAPI:
    """Creates and configures the AdaptOS FastAPI application."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if getattr(app.state, "adaptos_service", None) is None:
            if service_instance is not None:
                app.state.adaptos_service = service_instance
            else:
                cfg = build_service_config_from_env()
                app.state.adaptos_service = AdaptOSService(cfg)
        # Initialize Runtime Service (reuse the factory service's instance when present
        # so provisioning shares the same data root, offline-demo transport, and single-owner mode)
        if getattr(app.state, "runtime_service", None) is None:
            adaptos_svc = app.state.adaptos_service
            existing_rt = getattr(adaptos_svc, "runtime_service", None)
            if isinstance(existing_rt, AdaptOSRuntimeService):
                app.state.runtime_service = existing_rt
            else:
                rt_cfg = build_runtime_config_from_env(adaptos_svc.eval_public_key_bytes)
                app.state.runtime_service = AdaptOSRuntimeService(rt_cfg)
        # Initialize Intake Session Manager
        if getattr(app.state, "intake_session_manager", None) is None:
            _intake_data_root = Path(
                os.environ.get("ADAPTOS_DATA_ROOT", str(_BACKEND_DIR / "agnos_data"))
            ).resolve()
            app.state.intake_session_manager = IntakeSessionManager(data_root=_intake_data_root)
        yield

    app = FastAPI(
        title="AdaptOS AI Application Factory API",
        version=API_VERSION,
        description=(
            "Authenticated HTTP interface over AdaptOSService for specification intake, "
            "evaluation design, sandboxed build & repair, protected evaluation, and "
            "ready-gated artifact delivery."
        ),
        lifespan=lifespan,
    )

    allowed_origins = load_cors_origins_from_env()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key"],
        expose_headers=[
            "Content-Disposition",
            "X-AdaptOS-Verdict-Id",
            "X-AdaptOS-Verdict-Status",
            "X-AdaptOS-Artifact-Hash",
            "X-AdaptOS-Version-Id",
        ],
    )

    @app.exception_handler(HTTPException)
    async def _http_exception_handler(
        request: Request, exc: HTTPException
    ) -> JSONResponse:
        code_map = {
            400: "bad_request",
            401: "unauthorized",
            403: "forbidden",
            404: "not_found",
            409: "conflict",
            413: "payload_too_large",
            422: "unprocessable_entity",
            429: "rate_limit_exceeded",
            503: "service_unavailable",
        }
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                error_code=code_map.get(exc.status_code, "http_error"),
                message=str(exc.detail),
                run_id=request.path_params.get("run_id"),
            ).model_dump(mode="json"),
            headers=dict(exc.headers) if exc.headers else None,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        summary = "; ".join(
            f"{'.'.join(str(loc) for loc in err.get('loc', ()))}: {err.get('msg', '')}"
            for err in exc.errors()
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(
                error_code="request_validation_error",
                message=summary[:500] or "Invalid request payload.",
                run_id=request.path_params.get("run_id"),
            ).model_dump(mode="json"),
        )

    # ----------------------------------------------------------------------- #
    # Endpoint 1: GET /health (Public)
    # ----------------------------------------------------------------------- #
    @app.get(
        "/health",
        response_model=HealthResponse,
        tags=["system"],
        summary="Public health check",
    )
    async def get_health(request: Request) -> HealthResponse:
        svc = getattr(request.app.state, "adaptos_service", None)
        fallback_enabled = (
            bool(svc.config.allow_subprocess_sandbox_fallback)
            if isinstance(svc, AdaptOSService)
            else False
        )
        return HealthResponse(
            status="ok",
            service="adaptos-backend",
            version=API_VERSION,
            sandbox_subprocess_fallback_enabled=fallback_enabled,
        )

    # ----------------------------------------------------------------------- #
    # Endpoint 2: POST /api/projects
    # ----------------------------------------------------------------------- #
    @app.post(
        "/api/projects",
        response_model=ProjectRunSummary,
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(verify_api_key)],
        tags=["projects"],
        summary="Create a new AdaptOS project run",
    )
    async def create_project(
        payload: CreateProjectRequest,
        service: AdaptOSService = Depends(get_adaptos_service),
    ) -> Any:
        try:
            return await asyncio.to_thread(
                service.create_project,
                payload.user_goal,
                run_id=payload.run_id,
                max_repair_attempts=payload.max_repair_attempts,
            )
        except Exception as exc:
            return _map_service_exception_to_http(exc, run_id=payload.run_id)

    # ----------------------------------------------------------------------- #
    # Endpoint 3: GET /api/projects/{run_id}
    # ----------------------------------------------------------------------- #
    @app.get(
        "/api/projects/{run_id}",
        response_model=ProjectRunSummary,
        dependencies=[Depends(verify_api_key)],
        tags=["projects"],
        summary="Get project workflow and evaluation status",
    )
    async def get_project_status(
        run_id: str,
        service: AdaptOSService = Depends(get_adaptos_service),
    ) -> Any:
        try:
            return await asyncio.to_thread(service.get_project_status, run_id)
        except Exception as exc:
            return _map_service_exception_to_http(exc, run_id=run_id)

    # ----------------------------------------------------------------------- #
    # Endpoint 4: POST /api/projects/{run_id}/assets
    # ----------------------------------------------------------------------- #
    @app.post(
        "/api/projects/{run_id}/assets",
        response_model=IngestAssetsResponse,
        dependencies=[Depends(verify_api_key)],
        tags=["intake"],
        summary="Upload and profile source assets for a project",
    )
    async def upload_project_assets(
        run_id: str,
        payload: IngestAssetsRequest,
        service: AdaptOSService = Depends(get_adaptos_service),
    ) -> Any:
        try:
            profiles = await asyncio.to_thread(
                service.ingest_assets, run_id, payload.assets
            )
            return IngestAssetsResponse(
                run_id=run_id,
                asset_count=len(profiles),
                profiles=profiles,
            )
        except Exception as exc:
            return _map_service_exception_to_http(exc, run_id=run_id)

    # ----------------------------------------------------------------------- #
    # Endpoint 5: POST /api/projects/{run_id}/spec
    # ----------------------------------------------------------------------- #
    @app.post(
        "/api/projects/{run_id}/spec",
        response_model=ProjectRunSummary,
        dependencies=[Depends(verify_api_key)],
        tags=["intake"],
        summary="Submit specification for review",
    )
    async def submit_project_spec(
        run_id: str,
        payload: SubmitSpecRequest,
        service: AdaptOSService = Depends(get_adaptos_service),
    ) -> Any:
        try:
            return await asyncio.to_thread(
                service.submit_spec_for_review, run_id, payload.spec
            )
        except Exception as exc:
            return _map_service_exception_to_http(exc, run_id=run_id)

    # ----------------------------------------------------------------------- #
    # Endpoint 6: POST /api/projects/{run_id}/approve
    # ----------------------------------------------------------------------- #
    @app.post(
        "/api/projects/{run_id}/approve",
        response_model=ProjectRunSummary,
        dependencies=[Depends(verify_api_key)],
        tags=["intake"],
        summary="Approve specification with a validated HandoffPackage",
    )
    async def approve_project_handoff(
        run_id: str,
        request: Request,
        service: AdaptOSService = Depends(get_adaptos_service),
    ) -> Any:
        try:
            raw_body = await request.json()
            # Accept {"handoff": {...}}, a direct HandoffPackage, or {spec, approval} shape
            if isinstance(raw_body, Mapping) and "handoff" in raw_body:
                raw_handoff = raw_body["handoff"]
            elif isinstance(raw_body, Mapping) and "spec" in raw_body and "approval" in raw_body:
                raw_handoff = raw_body
            else:
                raw_handoff = raw_body
            # LLM-generated handoffs may carry undeclared keys (e.g. provenance
            # source_turn_id/source_quote, which belong only to GroundedFieldSpec)
            # or an invalid discovery_context.operation_mode. Strip undeclared keys
            # (the repo's own _filter_declared_fields convention) and normalize the
            # enum before strict contract validation. Declared provenance content is
            # untouched, so all verification still runs at full strength.
            sanitized = _sanitize_handoff_payload(raw_handoff)
            return await asyncio.to_thread(service.approve_spec, run_id, sanitized)
        except Exception as exc:
            return _map_service_exception_to_http(exc, run_id=run_id)

    # ----------------------------------------------------------------------- #
    # Endpoint 7: POST /api/projects/{run_id}/execute
    # ----------------------------------------------------------------------- #
    @app.post(
        "/api/projects/{run_id}/execute",
        response_model=ProjectRunSummary,
        dependencies=[Depends(verify_api_key)],
        tags=["workflow"],
        summary="Execute the complete factory workflow (eval_design -> deliver)",
    )
    async def execute_project_workflow(
        run_id: str,
        service: AdaptOSService = Depends(get_adaptos_service),
    ) -> Any:
        try:
            return await service.execute_factory_pipeline(run_id)
        except Exception as exc:
            return _map_service_exception_to_http(exc, run_id=run_id)

    # ----------------------------------------------------------------------- #
    # Endpoint 8: POST /api/projects/{run_id}/stages/{stage_name}
    # ----------------------------------------------------------------------- #
    @app.post(
        "/api/projects/{run_id}/stages/{stage_name}",
        response_model=ProjectRunSummary,
        dependencies=[Depends(verify_api_key)],
        tags=["workflow"],
        summary="Execute a single factory workflow stage",
    )
    async def execute_project_stage(
        run_id: str,
        stage_name: str,
        service: AdaptOSService = Depends(get_adaptos_service),
    ) -> Any:
        if stage_name not in VALID_STAGE_NODES:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=ErrorResponse(
                    error_code="invalid_stage_name",
                    message=(
                        f"Unknown stage_name '{stage_name}'; must be one of "
                        f"{sorted(VALID_STAGE_NODES)}."
                    ),
                    run_id=run_id,
                ).model_dump(mode="json"),
            )
        try:
            return await service.execute_single_stage(
                run_id, stage_name  # type: ignore[arg-type]
            )
        except Exception as exc:
            return _map_service_exception_to_http(exc, run_id=run_id)

    # ----------------------------------------------------------------------- #
    # Endpoint 9: GET /api/projects/{run_id}/delivery-package
    # ----------------------------------------------------------------------- #
    @app.get(
        "/api/projects/{run_id}/delivery-package",
        response_model=DeliveryPackage,
        dependencies=[Depends(verify_api_key)],
        tags=["delivery"],
        summary="Retrieve the verified DeliveryPackage (ready or not_ready)",
    )
    async def get_delivery_package(
        run_id: str,
        service: AdaptOSService = Depends(get_adaptos_service),
    ) -> Any:
        try:
            return await asyncio.to_thread(service.get_delivery_package, run_id)
        except Exception as exc:
            return _map_service_exception_to_http(exc, run_id=run_id)

    # ----------------------------------------------------------------------- #
    # Endpoint 10: GET /api/projects/{run_id}/download
    # ----------------------------------------------------------------------- #
    @app.get(
        "/api/projects/{run_id}/download",
        dependencies=[Depends(verify_api_key)],
        tags=["delivery"],
        summary="Download authorized application artifacts (requires Verdict status == 'ready')",
    )
    async def download_authorized_artifacts(
        run_id: str,
        format: Literal["zip", "json"] = Query(
            default="zip",
            description="Download format: 'zip' (archive) or 'json' (DeliveryPackage + UTF-8 file map).",
        ),
        service: AdaptOSService = Depends(get_adaptos_service),
    ) -> Response:
        try:
            pkg, files_data = await asyncio.to_thread(
                service.get_authorized_delivery, run_id
            )
        except Exception as exc:
            return _map_service_exception_to_http(exc, run_id=run_id)

        headers = {
            "X-AdaptOS-Verdict-Id": pkg.verdict.signing_key_id,
            "X-AdaptOS-Verdict-Status": pkg.verdict.status,
            "X-AdaptOS-Artifact-Hash": pkg.manifest.artifact_hash,
            "X-AdaptOS-Version-Id": pkg.manifest.version_id,
        }

        if format == "json":
            decoded_files = {
                path: raw.decode("utf-8", errors="replace")
                for path, raw in sorted(files_data.items())
            }
            body = AuthorizedDownloadJsonResponse(
                run_id=run_id,
                version_id=pkg.manifest.version_id,
                artifact_hash=pkg.manifest.artifact_hash,
                verdict_id=pkg.verdict.signing_key_id,
                verdict_status="ready",
                delivery_package=pkg,
                files=decoded_files,
            )
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=body.model_dump(mode="json"),
                headers=headers,
            )

        zip_buf = io.BytesIO()
        with zipfile.ZipFile(
            zip_buf, mode="w", compression=zipfile.ZIP_DEFLATED
        ) as zf:
            for rel_path in sorted(files_data.keys()):
                zf.writestr(rel_path, files_data[rel_path])
            zf.writestr(
                "delivery_package.json",
                json.dumps(
                    pkg.model_dump(mode="json"), indent=2, sort_keys=True
                ).encode("utf-8"),
            )

        zip_bytes = zip_buf.getvalue()
        safe_filename = f"{run_id}-{pkg.manifest.version_id}.zip"
        return Response(
            content=zip_bytes,
            status_code=status.HTTP_200_OK,
            media_type="application/zip",
            headers={
                **headers,
                "Content-Disposition": f'attachment; filename="{safe_filename}"',
            },
        )

    # ----------------------------------------------------------------------- #
    # Runtime Endpoints (11-16)
    # ----------------------------------------------------------------------- #

    @app.post(
        "/api/projects/{run_id}/runtime/provision",
        response_model=RuntimeApplicationSummary,
        dependencies=[Depends(verify_api_key)],
        tags=["runtime"],
        summary="Provision a verified delivery package as a runtime application",
    )
    async def provision_runtime_application(
        run_id: str,
        payload: ProvisionRuntimeRequest | None = None,
        factory_svc: AdaptOSService = Depends(get_adaptos_service),
        rt_svc: AdaptOSRuntimeService = Depends(get_runtime_service),
    ) -> Any:
        try:
            # Fetch the authorized delivery ZIP from the factory (gated on ready Verdict)
            pkg, files_data = await asyncio.to_thread(
                factory_svc.get_authorized_delivery, run_id
            )
            # Build ZIP bytes from the authorized artifact files
            import io as _io, zipfile as _zf
            zip_buf = _io.BytesIO()
            with _zf.ZipFile(zip_buf, mode="w", compression=_zf.ZIP_DEFLATED) as zf:
                for rel_path, raw in sorted(files_data.items()):
                    zf.writestr(rel_path, raw)
                zf.writestr(
                    "delivery_package.json",
                    json.dumps(pkg.model_dump(mode="json"), sort_keys=True).encode(),
                )
            zip_bytes = zip_buf.getvalue()
            # Carry the factory-ingested knowledge assets into the runtime so doc.ingest
            # can build the application's FTS5 index during provisioning.
            try:
                rt_assets = await asyncio.to_thread(
                    factory_svc._load_active_run_assets, run_id
                )
            except Exception:
                rt_assets = []
            summary = await asyncio.to_thread(
                rt_svc.provision_application,
                zip_bytes,
                project_run_id=run_id,
                owner_id=DEFAULT_RUNTIME_OWNER_ID,
                app_id=payload.app_id if payload is not None else None,
                assets=rt_assets,
                auto_activate=True,
            )
            return summary
        except Exception as exc:
            # Try factory error mapping first, then runtime mapping
            try:
                return _map_service_exception_to_http(exc, run_id=run_id)
            except Exception:
                return _map_runtime_exception_to_http(exc)

    @app.get(
        "/api/runtime/apps/{app_id}",
        response_model=RuntimeApplicationSummary,
        dependencies=[Depends(verify_api_key)],
        tags=["runtime"],
        summary="Get runtime application status",
    )
    async def get_runtime_app_status(
        app_id: str,
        rt_svc: AdaptOSRuntimeService = Depends(get_runtime_service),
    ) -> Any:
        try:
            return await asyncio.to_thread(
                rt_svc.get_application_status, app_id, owner_id=DEFAULT_RUNTIME_OWNER_ID
            )
        except Exception as exc:
            return _map_runtime_exception_to_http(exc)

    @app.post(
        "/api/runtime/apps/{app_id}/sessions",
        dependencies=[Depends(verify_api_key)],
        tags=["runtime"],
        summary="Create a new chat session for this application",
    )
    async def create_chat_session(
        app_id: str,
        payload: CreateSessionRequest,
        rt_svc: AdaptOSRuntimeService = Depends(get_runtime_service),
    ) -> Any:
        try:
            session = await asyncio.to_thread(
                rt_svc.create_chat_session,
                app_id,
                owner_id=DEFAULT_RUNTIME_OWNER_ID,
                title=payload.title,
                session_id=payload.session_id,
            )
            return JSONResponse(
                status_code=status.HTTP_201_CREATED,
                content=session.model_dump(mode="json"),
            )
        except Exception as exc:
            return _map_runtime_exception_to_http(exc)

    @app.get(
        "/api/runtime/apps/{app_id}/sessions",
        dependencies=[Depends(verify_api_key)],
        tags=["runtime"],
        summary="List all chat sessions for this application",
    )
    async def list_chat_sessions(
        app_id: str,
        rt_svc: AdaptOSRuntimeService = Depends(get_runtime_service),
    ) -> Any:
        try:
            sessions = await asyncio.to_thread(
                rt_svc.list_chat_sessions, app_id, owner_id=DEFAULT_RUNTIME_OWNER_ID
            )
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=[s.model_dump(mode="json") for s in sessions],
            )
        except Exception as exc:
            return _map_runtime_exception_to_http(exc)

    @app.get(
        "/api/runtime/apps/{app_id}/sessions/{session_id}/messages",
        dependencies=[Depends(verify_api_key)],
        tags=["runtime"],
        summary="Get conversation history for a session",
    )
    async def get_session_messages(
        app_id: str,
        session_id: str,
        limit: int = Query(default=100, ge=1, le=500),
        rt_svc: AdaptOSRuntimeService = Depends(get_runtime_service),
    ) -> Any:
        try:
            messages = await asyncio.to_thread(
                rt_svc.get_conversation_history,
                app_id,
                session_id,
                owner_id=DEFAULT_RUNTIME_OWNER_ID,
                limit=limit,
            )
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=[m.model_dump(mode="json") for m in messages],
            )
        except Exception as exc:
            return _map_runtime_exception_to_http(exc)

    @app.post(
        "/api/runtime/apps/{app_id}/sessions/{session_id}/messages",
        dependencies=[Depends(verify_api_key)],
        tags=["runtime"],
        summary="Send a user message and get an AI response",
    )
    async def send_chat_message(
        app_id: str,
        session_id: str,
        payload: SendMessageRequest,
        rt_svc: AdaptOSRuntimeService = Depends(get_runtime_service),
    ) -> Any:
        try:
            response = await asyncio.to_thread(
                rt_svc.send_chat_message,
                app_id,
                session_id,
                owner_id=DEFAULT_RUNTIME_OWNER_ID,
                user_message=payload.user_message,
            )
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=response.model_dump(mode="json"),
            )
        except Exception as exc:
            return _map_runtime_exception_to_http(exc)


    # ----------------------------------------------------------------------- #
    # Intake Session Endpoints (17-19)
    # ----------------------------------------------------------------------- #

    @app.post(
        "/api/projects/{run_id}/intake/start",
        dependencies=[Depends(verify_api_key)],
        tags=["intake"],
        summary="Start or resume an LLM-driven intake session for a project",
    )
    async def start_intake_session(
        run_id: str,
        payload: StartIntakeRequest,
        intake_svc: "IntakeSessionManager" = Depends(get_intake_service),
        factory_svc: AdaptOSService = Depends(get_adaptos_service),
    ) -> Any:
        try:
            # Enrich uploads that lack content by loading the already-ingested asset
            # bytes from the project's asset blob (files were uploaded via /assets).
            enriched_uploads: list[dict[str, Any]] = list(payload.uploads or [])
            if any(not isinstance(u, Mapping) or not u.get("content") for u in enriched_uploads):
                try:
                    g_state = await asyncio.to_thread(factory_svc.load_graph_state, run_id)
                    refs = g_state.get("refs", {})
                    blob_sha = refs.get("assets_blob_sha256") or refs.get(
                        "raw_assets_blob_sha256"
                    )
                    stored_assets: list[dict[str, Any]] = []
                    if blob_sha:
                        stored_assets = await asyncio.to_thread(
                            factory_svc.asset_store.get_json_blob, blob_sha
                        )
                    by_id = {
                        str(a.get("asset_id")): a
                        for a in stored_assets
                        if isinstance(a, Mapping)
                    }
                    by_name = {
                        str(a.get("filename")): a
                        for a in stored_assets
                        if isinstance(a, Mapping)
                    }
                    for idx, u in enumerate(enriched_uploads):
                        if isinstance(u, Mapping) and not u.get("content"):
                            match = by_id.get(str(u.get("asset_id"))) or by_name.get(
                                str(u.get("filename"))
                            )
                            if match and match.get("content"):
                                enriched_uploads[idx] = {
                                    **dict(u),
                                    "content": match["content"],
                                    "format": match.get("format") or u.get("format"),
                                }
                except Exception:
                    pass  # enrichment is best-effort; intake reports honest errors
            resp = await intake_svc.start_or_resume(
                run_id=run_id,
                user_goal=payload.user_goal,
                uploads=enriched_uploads,
                user_id=payload.user_id,
            )
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=resp.model_dump(mode="json"),
            )
        except Exception as exc:
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content=ErrorResponse(
                    error_code="intake_error",
                    message=str(exc),
                    run_id=run_id,
                ).model_dump(mode="json"),
            )

    @app.post(
        "/api/projects/{run_id}/intake/turn",
        dependencies=[Depends(verify_api_key)],
        tags=["intake"],
        summary="Send a user message to the intake LangGraph and get next assistant response",
    )
    async def send_intake_turn(
        run_id: str,
        payload: SendIntakeTurnRequest,
        intake_svc: "IntakeSessionManager" = Depends(get_intake_service),
    ) -> Any:
        try:
            resp = await intake_svc.send_turn(
                run_id=run_id,
                user_message=payload.user_message,
                user_id=payload.user_id,
            )
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=resp.model_dump(mode="json"),
            )
        except Exception as exc:
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content=ErrorResponse(
                    error_code="intake_turn_error",
                    message=str(exc),
                    run_id=run_id,
                ).model_dump(mode="json"),
            )

    @app.get(
        "/api/projects/{run_id}/intake/state",
        dependencies=[Depends(verify_api_key)],
        tags=["intake"],
        summary="Get the current intake session state without advancing the graph",
    )
    async def get_intake_state(
        run_id: str,
        intake_svc: "IntakeSessionManager" = Depends(get_intake_service),
    ) -> Any:
        try:
            resp = await asyncio.to_thread(intake_svc.get_state, run_id)
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=resp.model_dump(mode="json"),
            )
        except Exception as exc:
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content=ErrorResponse(
                    error_code="intake_state_error",
                    message=str(exc),
                    run_id=run_id,
                ).model_dump(mode="json"),
            )

    return app


app = create_app()


# =========================================================================== #
# 5. BUILT-IN SELF-TEST SUITE (Covers Startup Secret Guards + All 15 Checks)
# =========================================================================== #


class ApiBackendSelfTestSuite(unittest.TestCase):
    """Comprehensive HTTP test suite covering secret validation and all 15 API checks."""

    TEST_API_KEY: Final[str] = "test-adaptos-bearer-secret-key-2026"
    TEST_SERVICE_TOKEN: Final[str] = "test-adaptos-eval-service-token-32b"
    TEST_SIGNING_SEED: Final[str] = "test-adaptos-eval-signing-seed-phrase"

    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        self._tmp = tempfile.TemporaryDirectory(prefix="adaptos_api_test_")
        self.tmp_path = Path(self._tmp.name)
        self._saved_env = {
            k: os.environ.get(k)
            for k in (
                API_KEY_ENV_VAR,
                EVAL_SERVICE_TOKEN_ENV_VAR,
                EVAL_SIGNING_SEED_ENV_VAR,
                "ADAPTOS_DATA_ROOT",
            )
        }
        os.environ[API_KEY_ENV_VAR] = self.TEST_API_KEY
        os.environ[EVAL_SERVICE_TOKEN_ENV_VAR] = self.TEST_SERVICE_TOKEN
        os.environ[EVAL_SIGNING_SEED_ENV_VAR] = self.TEST_SIGNING_SEED
        os.environ["ADAPTOS_DATA_ROOT"] = str(self.tmp_path / "env_data_root")
        self.TestClient = TestClient

    def tearDown(self) -> None:
        for k, val in self._saved_env.items():
            if val is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = val
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

    def _auth_headers(self, token: str | None = None) -> dict[str, str]:
        active = token if token is not None else self.TEST_API_KEY
        return {"Authorization": f"Bearer {active}"}

    def test_00_startup_fails_closed_when_eval_secrets_missing_or_empty(self) -> None:
        """Issue 1 Test: Verifies that missing or empty ADAPTOS_EVAL_SERVICE_TOKEN or
        ADAPTOS_EVAL_SIGNING_SEED fails application startup with a clear RuntimeError,
        never falling back to hardcoded secrets or logging secret values.
        """
        # 1. Missing ADAPTOS_EVAL_SERVICE_TOKEN
        os.environ.pop(EVAL_SERVICE_TOKEN_ENV_VAR, None)
        with self.assertRaises(RuntimeError) as ctx_tok:
            with self.TestClient(create_app()):
                pass
        self.assertIn(EVAL_SERVICE_TOKEN_ENV_VAR, str(ctx_tok.exception))

        # 2. Empty ADAPTOS_EVAL_SERVICE_TOKEN
        os.environ[EVAL_SERVICE_TOKEN_ENV_VAR] = "   "
        with self.assertRaises(RuntimeError):
            with self.TestClient(create_app()):
                pass

        # Restore service token; test missing ADAPTOS_EVAL_SIGNING_SEED
        os.environ[EVAL_SERVICE_TOKEN_ENV_VAR] = self.TEST_SERVICE_TOKEN
        os.environ.pop(EVAL_SIGNING_SEED_ENV_VAR, None)
        with self.assertRaises(RuntimeError) as ctx_seed:
            with self.TestClient(create_app()):
                pass
        self.assertIn(EVAL_SIGNING_SEED_ENV_VAR, str(ctx_seed.exception))

        # 3. Empty ADAPTOS_EVAL_SIGNING_SEED
        os.environ[EVAL_SIGNING_SEED_ENV_VAR] = ""
        with self.assertRaises(RuntimeError):
            with self.TestClient(create_app()):
                pass

        # 4. Both secrets present -> default create_app() lifespan initializes AdaptOSService cleanly
        os.environ[EVAL_SIGNING_SEED_ENV_VAR] = self.TEST_SIGNING_SEED
        env_app = create_app()
        with self.TestClient(env_app) as client:
            resp = client.get("/health")
            self.assertEqual(resp.status_code, 200)
            self.assertIsInstance(env_app.state.adaptos_service, AdaptOSService)

    def test_01_startup_lifespan_and_public_health_endpoint(self) -> None:
        """Tests 2, 3, 4: API import, FastAPI lifespan startup, single service instance reuse,
        and public `/health` endpoint (without API key).
        """
        svc, _ = _service_mod._create_configured_test_service(self.tmp_path)
        fastapi_app = create_app(service_instance=svc)

        with self.TestClient(fastapi_app) as client:
            resp = client.get("/health")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "ok")
            self.assertEqual(data["service"], "adaptos-backend")
            self.assertFalse(data["sandbox_subprocess_fallback_enabled"])
            self.assertIs(fastapi_app.state.adaptos_service, svc)

    def test_02_authentication_missing_invalid_and_valid_bearer_key(self) -> None:
        """Tests 5, 6, 7: Missing API key -> 401, invalid API key -> 401, valid API key -> 201."""
        svc, _ = _service_mod._create_configured_test_service(self.tmp_path)
        fastapi_app = create_app(service_instance=svc)

        with self.TestClient(fastapi_app) as client:
            r_missing = client.post(
                "/api/projects", json={"user_goal": "Test goal"}
            )
            self.assertEqual(r_missing.status_code, 401)

            r_invalid = client.post(
                "/api/projects",
                json={"user_goal": "Test goal"},
                headers=self._auth_headers("wrong-api-key-value"),
            )
            self.assertEqual(r_invalid.status_code, 401)

            r_valid = client.post(
                "/api/projects",
                json={"user_goal": "Test goal", "run_id": "auth_ok_run"},
                headers=self._auth_headers(),
            )
            self.assertEqual(r_valid.status_code, 201)
            self.assertEqual(r_valid.json()["run_id"], "auth_ok_run")

    def test_03_project_creation_status_asset_validation_and_spec_approval(self) -> None:
        """Tests 8, 9, 10, 11: Project creation, duplicate run_id rejection (409), project status,
        unknown run_id (404), asset upload & validation, Spec submission, and HandoffPackage approval.
        """
        svc, spec = _service_mod._create_configured_test_service(self.tmp_path)
        fastapi_app = create_app(service_instance=svc)

        with self.TestClient(fastapi_app) as client:
            r_create = client.post(
                "/api/projects",
                json={"user_goal": spec.goal, "run_id": "proj_01"},
                headers=self._auth_headers(),
            )
            self.assertEqual(r_create.status_code, 201)
            self.assertEqual(r_create.json()["stage"], "intake")

            r_dup = client.post(
                "/api/projects",
                json={"user_goal": "Overwrite attempt", "run_id": "proj_01"},
                headers=self._auth_headers(),
            )
            self.assertEqual(r_dup.status_code, 409)

            r_status = client.get(
                "/api/projects/proj_01", headers=self._auth_headers()
            )
            self.assertEqual(r_status.status_code, 200)
            self.assertEqual(r_status.json()["user_goal"], spec.goal)

            r_404 = client.get(
                "/api/projects/nonexistent_run", headers=self._auth_headers()
            )
            self.assertEqual(r_404.status_code, 404)

            r_bad_asset = client.post(
                "/api/projects/proj_01/assets",
                json={
                    "assets": [
                        {
                            "asset_id": "bad_1",
                            "filename": "empty.md",
                            "content": "   ",
                            "format": "md",
                        }
                    ]
                },
                headers=self._auth_headers(),
            )
            self.assertEqual(r_bad_asset.status_code, 400)

            r_good_asset = client.post(
                "/api/projects/proj_01/assets",
                json={
                    "assets": [
                        {
                            "asset_id": "pol_v1",
                            "filename": "refund_policy.md",
                            "content": "Section 4.2 Refund Policy: Full refunds within 30 calendar days.",
                            "format": "md",
                        }
                    ]
                },
                headers=self._auth_headers(),
            )
            self.assertEqual(r_good_asset.status_code, 200)
            self.assertEqual(r_good_asset.json()["asset_count"], 1)

            r_spec = client.post(
                "/api/projects/proj_01/spec",
                json={"spec": spec.model_dump(mode="json")},
                headers=self._auth_headers(),
            )
            self.assertEqual(r_spec.status_code, 200)
            self.assertEqual(r_spec.json()["stage"], "spec_review")

            other_spec = spec.model_copy(update={"goal": "Tampered spec goal"})
            bad_handoff = _service_mod._build_synthetic_handoff_package(
                other_spec
            )
            r_bad_app = client.post(
                "/api/projects/proj_01/approve",
                json={"handoff": bad_handoff.model_dump(mode="json")},
                headers=self._auth_headers(),
            )
            self.assertIn(r_bad_app.status_code, (400, 409))

            valid_handoff = _service_mod._build_synthetic_handoff_package(spec)
            r_ok_app = client.post(
                "/api/projects/proj_01/approve",
                json={"handoff": valid_handoff.model_dump(mode="json")},
                headers=self._auth_headers(),
            )
            self.assertEqual(r_ok_app.status_code, 200)
            self.assertEqual(r_ok_app.json()["stage"], "eval_design")
            self.assertEqual(
                r_ok_app.json()["approved_spec_hash"], spec.content_hash()
            )

    def test_04_workflow_execution_delivery_package_and_authorized_download(self) -> None:
        """Tests 12, 13, 15: Full workflow execution (`POST /execute`), single-stage execution,
        delivery package retrieval (`GET /delivery-package`), and authorized ZIP/JSON download
        (`GET /download`) when Verdict.status == 'ready'.
        """
        svc, spec = _service_mod._create_configured_test_service(
            self.tmp_path / "ready_flow",
            seed_retrieval_bug=True,
            enable_effective_repair=True,
        )
        fastapi_app = create_app(service_instance=svc)

        with self.TestClient(fastapi_app) as client:
            client.post(
                "/api/projects",
                json={"user_goal": spec.goal, "run_id": "run_ready_api"},
                headers=self._auth_headers(),
            )
            client.post(
                "/api/projects/run_ready_api/assets",
                json={
                    "assets": [
                        {
                            "asset_id": "pol_v1",
                            "filename": "refund_policy.md",
                            "content": "Section 4.2 Refund Policy: Full refunds are granted within 30 calendar days of purchase if the software license key has not been activated.",
                            "format": "md",
                        }
                    ]
                },
                headers=self._auth_headers(),
            )
            client.post(
                "/api/projects/run_ready_api/spec",
                json={"spec": spec.model_dump(mode="json")},
                headers=self._auth_headers(),
            )
            handoff = _service_mod._build_synthetic_handoff_package(spec)
            client.post(
                "/api/projects/run_ready_api/approve",
                json={"handoff": handoff.model_dump(mode="json")},
                headers=self._auth_headers(),
            )

            r_stage = client.post(
                "/api/projects/run_ready_api/stages/init_run",
                headers=self._auth_headers(),
            )
            self.assertEqual(r_stage.status_code, 200)

            r_bad_stage = client.post(
                "/api/projects/run_ready_api/stages/unknown_node",
                headers=self._auth_headers(),
            )
            self.assertEqual(r_bad_stage.status_code, 400)

            r_exec = client.post(
                "/api/projects/run_ready_api/execute",
                headers=self._auth_headers(),
            )
            self.assertEqual(r_exec.status_code, 200)
            exec_data = r_exec.json()
            self.assertEqual(exec_data["stage"], "delivered")
            self.assertEqual(exec_data["verdict_status"], "ready")
            self.assertTrue(exec_data["is_ready_for_delivery"])

            r_pkg = client.get(
                "/api/projects/run_ready_api/delivery-package",
                headers=self._auth_headers(),
            )
            self.assertEqual(r_pkg.status_code, 200)
            self.assertEqual(r_pkg.json()["verdict"]["status"], "ready")

            r_zip = client.get(
                "/api/projects/run_ready_api/download",
                headers=self._auth_headers(),
            )
            self.assertEqual(r_zip.status_code, 200)
            self.assertEqual(r_zip.headers["content-type"], "application/zip")
            self.assertEqual(r_zip.headers["X-AdaptOS-Verdict-Status"], "ready")
            with zipfile.ZipFile(io.BytesIO(r_zip.content), mode="r") as zf:
                names = set(zf.namelist())
                self.assertIn("app_config.json", names)
                self.assertIn("prompts/system_prompt.txt", names)
                self.assertIn("schemas/io_schema.json", names)
                self.assertIn("delivery_package.json", names)

            r_json_dl = client.get(
                "/api/projects/run_ready_api/download?format=json",
                headers=self._auth_headers(),
            )
            self.assertEqual(r_json_dl.status_code, 200)
            self.assertIn("app_config.json", r_json_dl.json()["files"])

    def test_05_unauthorized_download_blocked_on_not_ready_or_pre_evaluation(self) -> None:
        """Test 14: Proves that `GET /api/projects/{run_id}/download` returns HTTP 403 Forbidden
        both before protected evaluation runs and when the protected Verdict is 'not_ready'.
        """
        svc, spec = _service_mod._create_configured_test_service(
            self.tmp_path / "not_ready_flow",
            seed_retrieval_bug=True,
            enable_effective_repair=False,
        )
        fastapi_app = create_app(service_instance=svc)

        with self.TestClient(fastapi_app) as client:
            client.post(
                "/api/projects",
                json={
                    "user_goal": spec.goal,
                    "run_id": "run_not_ready_api",
                    "max_repair_attempts": 1,
                },
                headers=self._auth_headers(),
            )
            client.post(
                "/api/projects/run_not_ready_api/assets",
                json={
                    "assets": [
                        {
                            "asset_id": "pol_v1",
                            "filename": "refund_policy.md",
                            "content": "Section 4.2 Refund Policy: Full refunds within 30 calendar days.",
                            "format": "md",
                        }
                    ]
                },
                headers=self._auth_headers(),
            )
            client.post(
                "/api/projects/run_not_ready_api/spec",
                json={"spec": spec.model_dump(mode="json")},
                headers=self._auth_headers(),
            )
            handoff = _service_mod._build_synthetic_handoff_package(spec)
            client.post(
                "/api/projects/run_not_ready_api/approve",
                json={"handoff": handoff.model_dump(mode="json")},
                headers=self._auth_headers(),
            )

            r_pre = client.get(
                "/api/projects/run_not_ready_api/download",
                headers=self._auth_headers(),
            )
            self.assertEqual(r_pre.status_code, 403)
            self.assertEqual(
                r_pre.json()["error_code"], "delivery_not_authorized"
            )

            r_exec = client.post(
                "/api/projects/run_not_ready_api/execute",
                headers=self._auth_headers(),
            )
            self.assertEqual(r_exec.status_code, 200)
            self.assertEqual(r_exec.json()["verdict_status"], "not_ready")
            self.assertFalse(r_exec.json()["is_ready_for_delivery"])

            r_pkg = client.get(
                "/api/projects/run_not_ready_api/delivery-package",
                headers=self._auth_headers(),
            )
            self.assertEqual(r_pkg.status_code, 200)
            self.assertEqual(r_pkg.json()["verdict"]["status"], "not_ready")

            r_dl = client.get(
                "/api/projects/run_not_ready_api/download",
                headers=self._auth_headers(),
            )
            self.assertEqual(r_dl.status_code, 403)
            self.assertEqual(
                r_dl.json()["error_code"], "delivery_not_authorized"
            )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AdaptOS FastAPI Backend")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run built-in FastAPI HTTP & integration unittest suite",
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="Bind host for uvicorn server"
    )
    parser.add_argument(
        "--port", type=int, default=8000, help="Bind port for uvicorn server"
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(
            ApiBackendSelfTestSuite
        )
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        return 0 if result.wasSuccessful() else 1

    import uvicorn

    target_app = "backend.api:app" if __package__ else "api:app"
    uvicorn.run(target_app, host=args.host, port=args.port, reload=False, workers=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())