
import os
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class FactorySettings(BaseSettings):
    """Settings available to the trusted factory process."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    factory_model_provider: str = "meta"
    factory_model_name: str = ""
    factory_api_key: SecretStr = SecretStr("")
    factory_base_url: str = ""

    factory_database_url: str = "sqlite:///data/factory/agnos.db"
    factory_artifact_dir: str = "data/factory/artifacts"

    factory_session_secret: SecretStr = SecretStr("")
    factory_eval_url: str = "http://127.0.0.1:8001"
    factory_eval_token: SecretStr = SecretStr("")
    factory_eval_public_key: str = ""

    factory_max_repair_attempts: int = 3
    factory_max_run_cost: float = 1.0


class EvalSettings(BaseSettings):
    """Settings available only to the evaluator process."""

    model_config = SettingsConfigDict(
        env_file=".env.eval",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    eval_vault_dir: str = "data/vault"
    eval_database_url: str = "sqlite:///data/vault/eval.db"
    eval_service_token: SecretStr = SecretStr("")
    eval_judge_api_key: SecretStr = SecretStr("")
    eval_signing_private_key: SecretStr = SecretStr("")
    eval_model_name: str = ""
    eval_model_base_url: str = ""


def load_factory_settings() -> FactorySettings:
    """Load factory settings without loading evaluator secrets."""

    if os.getenv("AGNOS_PROCESS_ROLE", "factory") != "factory":
        raise RuntimeError("Factory process role is not permitted.")

    return FactorySettings()


def load_eval_settings() -> EvalSettings:
    """Load evaluator settings without loading factory credentials."""

    if os.getenv("AGNOS_PROCESS_ROLE") != "eval":
        raise RuntimeError("Set AGNOS_PROCESS_ROLE=eval for the evaluator.")

    return EvalSettings()
