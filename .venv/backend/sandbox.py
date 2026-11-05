"""sandbox.py — Isolated Execution & AST Verification Layer for AdaptOS Generated Code.

Leaf module: depends ONLY on Python stdlib, Pydantic, and backend/schemas.py.
Never imports runtime.py, builder.py, repair.py, graph.py, or storage.py.
"""
from __future__ import annotations

import argparse
import ast
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Literal, Mapping, Protocol, Sequence

# Ensure backend/ root is on sys.path whether imported from repo root, backend/, or backend/agent(s)/
_CURRENT_DIR = Path(__file__).resolve().parent
_PARENT_DIR = _CURRENT_DIR.parent
for _cand_dir in (_CURRENT_DIR, _PARENT_DIR):
    if (_cand_dir / "schemas.py").is_file() and str(_cand_dir) not in sys.path:
        sys.path.insert(0, str(_cand_dir))
        break

from pydantic import BaseModel, ConfigDict, Field

try:
    from schemas import (
        ArtifactFile,
        Identifier,
        RuntimeLimits,
        Sha256Hex,
        canonical_json,
        sha256_hex,
    )
except ImportError:
    from backend.schemas import (  # type: ignore[no-redef]
        ArtifactFile,
        Identifier,
        RuntimeLimits,
        Sha256Hex,
        canonical_json,
        sha256_hex,
    )


# =========================================================================== #
# 1. CONSTANTS & BASE MODELS
# =========================================================================== #

ALLOWED_CODEGEN_IMPORTS: frozenset[str] = frozenset(
    {
        "math",
        "re",
        "json",
        "datetime",
        "decimal",
        "statistics",
        "collections",
        "itertools",
        "functools",
        "typing",
    }
)

# Note: 'input' is allowed ONLY as a bound parameter read inside `def run(input: dict, config: dict) -> dict`.
# Calls to `input(...)` and unbound references to `input` are blocked in AST validation.
BANNED_AST_NAMES: frozenset[str] = frozenset(
    {
        "eval",
        "exec",
        "open",
        "compile",
        "__import__",
        "breakpoint",
        "globals",
        "locals",
        "vars",
        "dir",
        "getattr",
        "setattr",
        "delattr",
    }
)

BANNED_AST_CALL_NAMES: frozenset[str] = BANNED_AST_NAMES | {"input"}

BANNED_AST_MODULES: frozenset[str] = frozenset(
    {
        "os",
        "sys",
        "subprocess",
        "socket",
        "pathlib",
        "shutil",
        "urllib",
        "http",
        "requests",
        "httpx",
        "aiohttp",
        "pickle",
        "marshal",
        "ctypes",
        "multiprocessing",
        "threading",
        "importlib",
        "builtins",
    }
)

_SECRET_PATTERN: re.Pattern[str] = re.compile(
    r"(sk-[A-Za-z0-9]{16,}|MODEL_API_KEY|ADAPTOS_ACCESS_SECRET|Bearer\s+[A-Za-z0-9._\-]{16,})"
)

IsolationMode = Literal["docker", "modal", "subprocess_dev_isolated", "blocked"]

_SANDBOX_RUNNER_SCRIPT: str = """
import builtins
import copy
import io
import json
import sys

ALLOWED_MODULES = {
    "math", "re", "json", "datetime", "decimal", "statistics",
    "collections", "itertools", "functools", "typing", "_io", "time"
}
_orig_import = builtins.__import__
_orig_exec = builtins.exec
_real_stdout = sys.stdout
_real_stderr = sys.stderr

def _run_isolated():
    raw_payload = sys.stdin.read()
    sys.stdin = io.StringIO("")
    payload = json.loads(raw_payload)
    source_code = payload["source_code"]
    vectors = payload["vectors"]
    del raw_payload, payload

    def _safe_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level and level > 0:
            raise ImportError("Relative imports are blocked by AdaptOS sandbox policy.")
        root = name.split(".")[0]
        if root not in ALLOWED_MODULES:
            raise ImportError(f"Import of '{name}' is blocked by AdaptOS sandbox policy.")
        return _orig_import(name, globals, locals, fromlist, level)

    for _banned in (
        "open", "eval", "exec", "compile", "input", "breakpoint",
        "globals", "locals", "vars", "dir"
    ):
        setattr(builtins, _banned, None)
    builtins.__import__ = _safe_import

    namespace = {"__builtins__": builtins, "__name__": "__sandbox_fn__"}
    _orig_import("builtins")

    # Redirect stdout/stderr during module exec and run() so user code cannot corrupt
    # protocol output or leak hidden test inputs via print/stderr.
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    try:
        _orig_exec(source_code, namespace, namespace)
    except Exception as exc:
        sys.stdout = _real_stdout
        sys.stderr = _real_stderr
        _real_stderr.write(f"ModuleLoadError: {type(exc).__name__}\\n")
        sys.exit(1)

    run_fn = namespace.get("run")
    if not callable(run_fn):
        sys.stdout = _real_stdout
        sys.stderr = _real_stderr
        _real_stderr.write("MissingCallableError: run(input, config) is not callable\\n")
        sys.exit(1)

    results = []
    for vec in vectors:
        vid = str(vec.get("vector_id", "unknown"))
        in_copy_1 = copy.deepcopy(vec.get("input_payload", {}))
        cfg_copy_1 = copy.deepcopy(vec.get("config_payload", {}))
        in_copy_2 = copy.deepcopy(vec.get("input_payload", {}))
        cfg_copy_2 = copy.deepcopy(vec.get("config_payload", {}))
        try:
            out1 = run_fn(in_copy_1, cfg_copy_1)
            out2 = run_fn(in_copy_2, cfg_copy_2)
        except Exception as exc:
            sys.stdout = _real_stdout
            sys.stderr = _real_stderr
            _real_stderr.write(f"VectorExecutionError on vector '{vid}': {type(exc).__name__}\\n")
            sys.exit(1)

        if not isinstance(out1, dict) or not isinstance(out2, dict):
            sys.stdout = _real_stdout
            sys.stderr = _real_stderr
            _real_stderr.write(f"OutputTypeError on vector '{vid}': run() must return a dict\\n")
            sys.exit(1)

        if out1 != out2:
            sys.stdout = _real_stdout
            sys.stderr = _real_stderr
            _real_stderr.write(f"NonDeterministicOutputError on vector '{vid}'\\n")
            sys.exit(1)

        results.append({"vector_id": vid, "output": out1})

    sys.stdout = _real_stdout
    sys.stderr = _real_stderr
    _real_stdout.write(json.dumps({"ok": True, "results": results}))

_run_isolated()
"""


class StrictSandboxModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FrozenSandboxModel(StrictSandboxModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# =========================================================================== #
# 2. CONFIGURATION, PROTOCOLS & DATA CONTRACTS
# =========================================================================== #


@dataclass(frozen=True)
class SandboxConfig:
    max_generated_code_bytes: int = 100_000
    sandbox_timeout_seconds: int = 10
    sandbox_memory_mb: int = 256
    prefer_docker_sandbox: bool = True
    allow_subprocess_dev_fallback: bool = False


class TestVector(FrozenSandboxModel):
    vector_id: Identifier
    input_payload: dict[str, Any]
    config_payload: dict[str, Any] = Field(default_factory=dict)
    expected_subset: dict[str, Any] = Field(default_factory=dict)
    visibility: Literal["visible", "hidden"] = "visible"


class ValidationReport(FrozenSandboxModel):
    component_ref: str
    passed: bool
    isolation_mode: IsolationMode
    stage_results: dict[str, bool]
    failing_vectors_sanitized: tuple[str, ...] = ()
    wall_time_ms: int = 0
    error_summary: str = ""


class CodeGenTaskProtocol(Protocol):
    @property
    def component_id(self) -> str: ...
    @property
    def version(self) -> str: ...
    @property
    def output_schema(self) -> dict[str, Any]: ...
    @property
    def visible_test_vectors(self) -> Sequence[TestVector]: ...


class CodeGenResultProtocol(Protocol):
    @property
    def source_code(self) -> str: ...
    @property
    def declared_imports(self) -> Sequence[str]: ...


# =========================================================================== #
# 3. SANDBOX VERIFIER IMPLEMENTATION
# =========================================================================== #


def _collect_sensitive_strings(value: Any, out: set[str]) -> None:
    if isinstance(value, str):
        stripped = value.strip()
        if len(stripped) >= 4:
            out.add(stripped)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        s_val = str(value)
        if len(s_val) >= 4:
            out.add(s_val)
    elif isinstance(value, Mapping):
        for k, v in value.items():
            _collect_sensitive_strings(k, out)
            _collect_sensitive_strings(v, out)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            _collect_sensitive_strings(item, out)


def _scrub_hidden_test_data(text: str, hidden_vectors: Sequence[TestVector]) -> str:
    if not text or not hidden_vectors:
        return text
    sensitive_literals: set[str] = set()
    for hv in hidden_vectors:
        _collect_sensitive_strings(hv.input_payload, sensitive_literals)
        _collect_sensitive_strings(hv.config_payload, sensitive_literals)
        _collect_sensitive_strings(hv.expected_subset, sensitive_literals)

    scrubbed = text
    for literal in sorted(sensitive_literals, key=len, reverse=True):
        if literal in scrubbed:
            scrubbed = scrubbed.replace(literal, "[REDACTED_HIDDEN]")
    return scrubbed


class SandboxVerifier:
    """Deterministic AST/signature linter and isolated sandbox verifier for generated code."""

    def __init__(
        self,
        config: SandboxConfig | Any = None,
        *,
        docker_runner_override: Callable[
            [list[str], bytes, int], subprocess.CompletedProcess[bytes]
        ]
        | None = None,
    ) -> None:
        self.config = config or SandboxConfig()
        self.docker_runner_override = docker_runner_override

    def _docker_available(self) -> bool:
        if self.docker_runner_override is not None:
            return True
        if not shutil.which("docker"):
            return False
        try:
            proc = subprocess.run(
                ["docker", "info"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3,
                check=False,
            )
            return proc.returncode == 0
        except Exception:
            return False

    @staticmethod
    def lint_ast_and_signature(source_code: str) -> tuple[bool, bool, str]:
        """Returns (ast_ok, signature_ok, error_message).

        Validates imports against ALLOWED_CODEGEN_IMPORTS, blocks BANNED_AST_NAMES,
        BANNED_AST_CALL_NAMES (including `input()`), BANNED_AST_MODULES, and dunder access,
        and enforces top-level synchronous `def run(input: dict, config: dict) -> dict`.
        """
        if not isinstance(source_code, str) or not source_code.strip():
            return False, False, "Source code must be a non-empty string."

        try:
            tree = ast.parse(source_code)
        except SyntaxError as exc:
            return False, False, f"SyntaxError in generated code: {exc}"

        has_valid_run = False
        signature_error: str | None = None

        for top_node in tree.body:
            if isinstance(top_node, ast.AsyncFunctionDef) and top_node.name == "run":
                signature_error = (
                    "run() must be a synchronous function `def run(input: dict, config: dict) -> dict`."
                )
            elif isinstance(top_node, ast.FunctionDef) and top_node.name == "run":
                arg_names = [a.arg for a in top_node.args.args]
                posonly_names = [a.arg for a in getattr(top_node.args, "posonlyargs", [])]
                if (
                    posonly_names
                    or arg_names != ["input", "config"]
                    or top_node.args.vararg is not None
                    or top_node.args.kwarg is not None
                    or top_node.args.kwonlyargs
                ):
                    signature_error = (
                        "Invalid run() parameters: expected exact signature `def run(input: dict, config: dict) -> dict`."
                    )
                elif (
                    isinstance(top_node.returns, ast.Name)
                    and top_node.returns.id not in ("dict", "Dict", "Any", "Mapping")
                ):
                    signature_error = (
                        f"Invalid run() return annotation '{top_node.returns.id}': expected `dict`."
                    )
                else:
                    has_valid_run = True

        def _walk_with_scope(node: ast.AST, bound_params: frozenset[str]) -> str | None:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root in BANNED_AST_MODULES or root not in ALLOWED_CODEGEN_IMPORTS:
                        return f"Disallowed import: '{alias.name}'."
            elif isinstance(node, ast.ImportFrom):
                mod = (node.module or "").split(".")[0]
                if (
                    (node.level and node.level > 0)
                    or mod in BANNED_AST_MODULES
                    or mod not in ALLOWED_CODEGEN_IMPORTS
                ):
                    return f"Disallowed from-import: '{node.module}'."
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in BANNED_AST_CALL_NAMES:
                    return f"Banned builtin call '{node.func.id}()' in AST."
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in BANNED_AST_CALL_NAMES
                ):
                    return f"Banned attribute call '{node.func.attr}()' in AST."
            elif isinstance(node, ast.Name):
                if node.id in BANNED_AST_NAMES or (
                    node.id.startswith("__")
                    and node.id.endswith("__")
                    and node.id != "__name__"
                ):
                    return f"Banned identifier '{node.id}' in AST."
                if node.id == "input" and "input" not in bound_params:
                    return "Banned unbound builtin identifier 'input' in AST."
            elif isinstance(node, ast.Attribute):
                if node.attr.startswith("__") and node.attr.endswith("__"):
                    return f"Banned dunder attribute access '{node.attr}'."

            child_bound = bound_params
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                arg_list = [a.arg for a in node.args.args] + [
                    a.arg for a in node.args.kwonlyargs
                ]
                if node.args.vararg:
                    arg_list.append(node.args.vararg.arg)
                if node.args.kwarg:
                    arg_list.append(node.args.kwarg.arg)
                child_bound = bound_params | frozenset(arg_list)

            for child in ast.iter_child_nodes(node):
                err = _walk_with_scope(child, child_bound)
                if err is not None:
                    return err
            return None

        ast_err = _walk_with_scope(tree, frozenset())
        if ast_err is not None:
            return False, False, ast_err

        if signature_error is not None:
            return True, False, signature_error

        if not has_valid_run:
            return (
                True,
                False,
                "Missing required function signature `def run(input: dict, config: dict) -> dict`.",
            )
        return True, True, ""

    @staticmethod
    def validate_output_against_schema(
        output: dict[str, Any], schema: dict[str, Any]
    ) -> list[str]:
        """Validates `output` against a JSON Schema and returns structured error strings."""
        if not isinstance(output, dict):
            return ["Output is not a JSON object (dict)."]
        if not isinstance(schema, Mapping) or not schema:
            return []

        errors: list[str] = []

        def _check_node(val: Any, sub_schema: Mapping[str, Any], path_label: str) -> None:
            expected_t = sub_schema.get("type")
            if expected_t == "object":
                if not isinstance(val, dict):
                    errors.append(
                        f"Key '{path_label}' expected object, got {type(val).__name__}."
                    )
                    return
                req_keys = sub_schema.get("required", [])
                props = sub_schema.get("properties", {})
                for rk in req_keys:
                    if rk not in val:
                        full_rk = f"{path_label}.{rk}" if path_label else str(rk)
                        errors.append(f"Missing required output key '{full_rk}'.")
                if sub_schema.get("additionalProperties") is False and isinstance(props, Mapping):
                    for k in val:
                        if k not in props:
                            full_k = f"{path_label}.{k}" if path_label else str(k)
                            errors.append(f"Unexpected additional key '{full_k}'.")
                if isinstance(props, Mapping):
                    for k, child_val in val.items():
                        if k in props and isinstance(props[k], Mapping):
                            child_label = f"{path_label}.{k}" if path_label else str(k)
                            _check_node(child_val, props[k], child_label)
            elif expected_t == "array":
                if not isinstance(val, list):
                    errors.append(
                        f"Key '{path_label}' expected array, got {type(val).__name__}."
                    )
                    return
                min_items = sub_schema.get("minItems")
                if isinstance(min_items, int) and len(val) < min_items:
                    errors.append(
                        f"Key '{path_label}' expected at least {min_items} items, got {len(val)}."
                    )
                item_schema = sub_schema.get("items")
                if isinstance(item_schema, Mapping):
                    for idx, elem in enumerate(val):
                        _check_node(elem, item_schema, f"{path_label}[{idx}]")
            elif expected_t == "string":
                if not isinstance(val, str):
                    errors.append(
                        f"Key '{path_label}' expected string, got {type(val).__name__}."
                    )
            elif expected_t == "boolean":
                if not isinstance(val, bool):
                    errors.append(
                        f"Key '{path_label}' expected boolean, got {type(val).__name__}."
                    )
            elif expected_t == "integer":
                if not isinstance(val, int) or isinstance(val, bool):
                    errors.append(
                        f"Key '{path_label}' expected integer, got {type(val).__name__}."
                    )
            elif expected_t == "number":
                if not isinstance(val, (int, float)) or isinstance(val, bool):
                    errors.append(
                        f"Key '{path_label}' expected number, got {type(val).__name__}."
                    )
            elif expected_t == "null":
                if val is not None:
                    errors.append(
                        f"Key '{path_label}' expected null, got {type(val).__name__}."
                    )

            if "enum" in sub_schema and isinstance(sub_schema["enum"], list):
                if val not in sub_schema["enum"]:
                    errors.append(
                        f"Key '{path_label}' value {val!r} not in enum {sub_schema['enum']}."
                    )

        top_schema = dict(schema)
        if "type" not in top_schema and ("properties" in top_schema or "required" in top_schema):
            top_schema["type"] = "object"
        _check_node(output, top_schema, "")
        return errors

    @staticmethod
    def _validate_output_against_schema(
        output: dict[str, Any], schema: dict[str, Any]
    ) -> list[str]:
        return SandboxVerifier.validate_output_against_schema(output, schema)

    @staticmethod
    def value_matches_expected(actual: Any, expected: Any) -> bool:
        """Deterministic expected-value matcher supporting nested dicts, lists, scalars, and substrings."""
        if isinstance(expected, bool) or isinstance(actual, bool):
            return (
                isinstance(actual, bool)
                and isinstance(expected, bool)
                and (actual is expected)
            )

        if isinstance(expected, Mapping):
            if not isinstance(actual, Mapping):
                return False
            for k, exp_v in expected.items():
                if k not in actual:
                    return False
                if not SandboxVerifier.value_matches_expected(actual[k], exp_v):
                    return False
            return True

        if isinstance(expected, (list, tuple)):
            if not isinstance(actual, (list, tuple)) or len(actual) != len(expected):
                return False
            return all(
                SandboxVerifier.value_matches_expected(a_elem, e_elem)
                for a_elem, e_elem in zip(actual, expected)
            )

        if isinstance(expected, (int, float)):
            if not isinstance(actual, (int, float)) or isinstance(actual, bool):
                return False
            if isinstance(expected, int) and isinstance(actual, int):
                return actual == expected
            return math.isclose(float(actual), float(expected), rel_tol=1e-6, abs_tol=1e-6)

        if isinstance(expected, str):
            if not isinstance(actual, str):
                return False
            if actual == expected:
                return True
            if expected.strip():
                return expected.strip().lower() in actual.lower()
            return False

        return bool(actual == expected)

    @staticmethod
    def _value_matches_expected(actual: Any, expected: Any) -> bool:
        return SandboxVerifier.value_matches_expected(actual, expected)

    def execute_in_sandbox(
        self,
        source_code: str,
        vectors: Sequence[TestVector],
    ) -> tuple[bool, IsolationMode, list[dict[str, Any]], str]:
        """Executes `source_code` against `vectors` inside an isolated Docker container.

        Never sends `expected_subset` or `visibility` into the sandbox stdin payload,
        and scrubs any hidden vector values from error messages.
        """
        prefer_docker = bool(getattr(self.config, "prefer_docker_sandbox", True))
        allow_fallback = bool(
            getattr(self.config, "allow_subprocess_dev_fallback", False)
        )
        timeout_s = int(getattr(self.config, "sandbox_timeout_seconds", 10))
        memory_mb = int(getattr(self.config, "sandbox_memory_mb", 256))

        hidden_vecs = [v for v in vectors if v.visibility == "hidden"]

        # Strip expected_subset and visibility so generated code inside the worker can never inspect them
        worker_vectors = [
            {
                "vector_id": v.vector_id,
                "input_payload": v.input_payload,
                "config_payload": v.config_payload,
            }
            for v in vectors
        ]
        stdin_payload = json.dumps(
            {
                "source_code": source_code,
                "vectors": worker_vectors,
            }
        ).encode("utf-8")

        if prefer_docker and self._docker_available():
            mode: IsolationMode = "docker"
            cmd = [
                "docker",
                "run",
                "--rm",
                "-i",
                "--network",
                "none",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=16m",
                f"--memory={memory_mb}m",
                "--cpus=0.5",
                "--pids-limit=32",
                "--user",
                "65534:65534",
                "python:3.11-slim",
                "python",
                "-I",
                "-c",
                _SANDBOX_RUNNER_SCRIPT,
            ]
            if self.docker_runner_override is not None:
                try:
                    proc = self.docker_runner_override(cmd, stdin_payload, timeout_s)
                except subprocess.TimeoutExpired:
                    return (
                        False,
                        mode,
                        [],
                        f"Docker sandbox timed out after {timeout_s}s.",
                    )
                except Exception as exc:
                    safe_exc = _scrub_hidden_test_data(str(exc), hidden_vecs)
                    return (
                        False,
                        mode,
                        [],
                        f"Docker sandbox invocation failed: {safe_exc}",
                    )
            else:
                with tempfile.TemporaryDirectory(prefix="adaptos_sbx_") as sbx_dir:
                    try:
                        proc = subprocess.run(
                            cmd,
                            input=stdin_payload,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            cwd=sbx_dir,
                            env={},
                            timeout=timeout_s,
                            check=False,
                        )
                    except subprocess.TimeoutExpired:
                        return (
                            False,
                            mode,
                            [],
                            f"Docker sandbox timed out after {timeout_s}s.",
                        )
                    except Exception as exc:
                        safe_exc = _scrub_hidden_test_data(str(exc), hidden_vecs)
                        return (
                            False,
                            mode,
                            [],
                            f"Docker sandbox invocation failed: {safe_exc}",
                        )
        elif allow_fallback:
            mode = "subprocess_dev_isolated"
            cmd = [sys.executable, "-I", "-c", _SANDBOX_RUNNER_SCRIPT]
            env = {
                k: v
                for k, v in os.environ.items()
                if k.upper() in ("SYSTEMROOT", "PATH", "TEMP", "TMP")
            }
            with tempfile.TemporaryDirectory(prefix="adaptos_sbx_") as sbx_dir:
                try:
                    proc = subprocess.run(
                        cmd,
                        input=stdin_payload,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        cwd=sbx_dir,
                        env=env,
                        timeout=timeout_s,
                        check=False,
                    )
                except subprocess.TimeoutExpired:
                    return (
                        False,
                        mode,
                        [],
                        f"Sandbox execution timed out after {timeout_s}s.",
                    )
                except Exception as exc:
                    safe_exc = _scrub_hidden_test_data(str(exc), hidden_vecs)
                    return False, mode, [], f"Sandbox invocation failed: {safe_exc}"
        else:
            return (
                False,
                "blocked",
                [],
                "Secure Docker sandbox is unavailable and allow_subprocess_dev_fallback is False; failing closed.",
            )

        if proc.returncode != 0:
            raw_err = proc.stderr.decode("utf-8", errors="replace").strip()[-300:]
            safe_err = _scrub_hidden_test_data(raw_err, hidden_vecs)
            return False, mode, [], f"Sandbox runtime error: {safe_err}"

        try:
            parsed = json.loads(proc.stdout.decode("utf-8"))
            if not isinstance(parsed, dict) or not parsed.get("ok"):
                return False, mode, [], "Sandbox worker did not report ok=True."
            return True, mode, list(parsed.get("results", [])), ""
        except Exception as exc:
            return False, mode, [], f"Malformed sandbox stdout: {type(exc).__name__}"

    def verify_generated_component(
        self,
        *,
        task: CodeGenTaskProtocol | Any,
        result: CodeGenResultProtocol | Any,
        hidden_vectors: Sequence[TestVector],
    ) -> ValidationReport:
        """Executes the 6-stage static + sandbox + schema/assertion verification pipeline."""
        t0 = time.monotonic()
        comp_id = str(getattr(task, "component_id", "fn.unknown"))
        comp_ver = str(getattr(task, "version", "1.0.0"))
        comp_ref = f"{comp_id}@{comp_ver}"
        max_bytes = int(getattr(self.config, "max_generated_code_bytes", 100_000))

        stage_results: dict[str, bool] = {
            "1_size_path_secrets": False,
            "2_ast_lint": False,
            "3_signature_check": False,
            "4_visible_vectors": False,
            "5_hidden_vectors": False,
            "6_schema_and_determinism": False,
        }

        visible_vecs = list(getattr(task, "visible_test_vectors", ()))
        if any(v.visibility == "hidden" for v in visible_vecs):
            return ValidationReport(
                component_ref=comp_ref,
                passed=False,
                isolation_mode="blocked",
                stage_results=stage_results,
                wall_time_ms=max(1, int((time.monotonic() - t0) * 1000)),
                error_summary="Confidentiality violation: hidden test vector found inside visible_test_vectors.",
            )

        normalized_hidden: list[TestVector] = [
            v if v.visibility == "hidden" else v.model_copy(update={"visibility": "hidden"})
            for v in hidden_vectors
        ]

        source_code = str(getattr(result, "source_code", ""))
        declared_imports = list(getattr(result, "declared_imports", ()))
        raw_bytes = source_code.encode("utf-8")
        rel_path = f"generated/{comp_id}/{comp_ver}/fn.py"

        # Stage 1: Size, ArtifactFile path rules, declared imports, and secret scan
        try:
            if len(raw_bytes) == 0 or len(raw_bytes) > max_bytes:
                raise ValueError("Source code size is invalid or exceeds max_generated_code_bytes.")
            _ = ArtifactFile(
                path=rel_path,
                sha256=sha256_hex(raw_bytes),
                size_bytes=len(raw_bytes),
            )
            for imp in declared_imports:
                root_imp = str(imp).split(".")[0].strip()
                if root_imp and (
                    root_imp in BANNED_AST_MODULES
                    or root_imp not in ALLOWED_CODEGEN_IMPORTS
                ):
                    raise ValueError(f"Disallowed declared_import '{imp}'.")
            if _SECRET_PATTERN.search(source_code):
                raise ValueError("Secret-like token pattern detected in generated code.")
            stage_results["1_size_path_secrets"] = True
        except Exception as exc:
            return ValidationReport(
                component_ref=comp_ref,
                passed=False,
                isolation_mode="blocked",
                stage_results=stage_results,
                wall_time_ms=max(1, int((time.monotonic() - t0) * 1000)),
                error_summary=f"Stage 1 failed: {exc}",
            )

        # Stage 2 & 3: AST Lint & Signature Check
        ast_ok, sig_ok, lint_err = self.lint_ast_and_signature(source_code)
        stage_results["2_ast_lint"] = ast_ok
        stage_results["3_signature_check"] = sig_ok
        if not (ast_ok and sig_ok):
            return ValidationReport(
                component_ref=comp_ref,
                passed=False,
                isolation_mode="blocked",
                stage_results=stage_results,
                wall_time_ms=max(1, int((time.monotonic() - t0) * 1000)),
                error_summary=lint_err,
            )

        # Stage 4, 5 & 6: Execute visible + hidden vectors in isolated sandbox worker
        all_vectors = [*visible_vecs, *normalized_hidden]
        ok, mode, run_outputs, sbx_err = self.execute_in_sandbox(
            source_code, all_vectors
        )
        if not ok:
            safe_sbx_err = _scrub_hidden_test_data(sbx_err, normalized_hidden)
            return ValidationReport(
                component_ref=comp_ref,
                passed=False,
                isolation_mode=mode,
                stage_results=stage_results,
                wall_time_ms=max(1, int((time.monotonic() - t0) * 1000)),
                error_summary=safe_sbx_err,
            )

        failing_sanitized: list[str] = []
        vis_ids = {v.vector_id for v in visible_vecs}
        hid_ids = {v.vector_id for v in normalized_hidden}
        vec_map = {v.vector_id: v for v in all_vectors}
        output_schema = getattr(task, "output_schema", {"type": "object"})

        vis_ok = True
        hid_ok = True
        schema_ok = True

        for item in run_outputs:
            vid = str(item.get("vector_id", ""))
            out_dict = item.get("output")
            vec = vec_map.get(vid)
            if vec is None:
                continue

            is_hidden = vid in hid_ids or vec.visibility == "hidden"
            schema_errs = self.validate_output_against_schema(out_dict, output_schema)
            if schema_errs:
                schema_ok = False
                if is_hidden:
                    hid_ok = False
                    failing_sanitized.append(f"hidden_vector:{vid}")
                else:
                    vis_ok = False
                    clean_err = _scrub_hidden_test_data(
                        "; ".join(schema_errs), normalized_hidden
                    )
                    failing_sanitized.append(f"{vid}: schema mismatch ({clean_err})")

            for exp_k, exp_v in vec.expected_subset.items():
                actual_val = out_dict.get(exp_k) if isinstance(out_dict, Mapping) else None
                if not self.value_matches_expected(actual_val, exp_v):
                    if is_hidden:
                        hid_ok = False
                        if f"hidden_vector:{vid}" not in failing_sanitized:
                            failing_sanitized.append(f"hidden_vector:{vid}")
                    else:
                        vis_ok = False
                        failing_sanitized.append(
                            f"{vid}: expected {exp_k}={exp_v!r}, got {actual_val!r}"
                        )

        stage_results["4_visible_vectors"] = vis_ok
        stage_results["5_hidden_vectors"] = hid_ok
        stage_results["6_schema_and_determinism"] = schema_ok

        passed_all = all(stage_results.values())
        summary = _scrub_hidden_test_data(
            "; ".join(failing_sanitized), normalized_hidden
        )
        return ValidationReport(
            component_ref=comp_ref,
            passed=passed_all,
            isolation_mode=mode,
            stage_results=stage_results,
            failing_vectors_sanitized=tuple(failing_sanitized),
            wall_time_ms=max(1, int((time.monotonic() - t0) * 1000)),
            error_summary=summary if failing_sanitized else "",
        )


# =========================================================================== #
# 4. MVP SELF-TEST SUITE (Covers All 14 Required Scenarios)
# =========================================================================== #


def _simulated_docker_runner_for_tests(
    cmd: list[str], stdin_bytes: bytes, timeout_s: int
) -> subprocess.CompletedProcess[bytes]:
    """Executes the exact _SANDBOX_RUNNER_SCRIPT in an isolated `-I` process while verifying Docker flags."""
    assert cmd[0] == "docker" and "--network" in cmd and "none" in cmd and "--read-only" in cmd
    env = {
        k: v
        for k, v in os.environ.items()
        if k.upper() in ("SYSTEMROOT", "PATH", "TEMP", "TMP")
    }
    with tempfile.TemporaryDirectory(prefix="sbx_sim_docker_") as tmp_d:
        return subprocess.run(
            [sys.executable, "-I", "-c", _SANDBOX_RUNNER_SCRIPT],
            input=stdin_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=tmp_d,
            env=env,
            timeout=timeout_s,
            check=False,
        )


@dataclass(frozen=True)
class _DummyCodeGenTask:
    component_id: str = "fn.discount_calc"
    version: str = "1.0.0"
    output_schema: dict[str, Any] = None  # type: ignore[assignment]
    visible_test_vectors: tuple[TestVector, ...] = ()


@dataclass(frozen=True)
class _DummyCodeGenResult:
    source_code: str
    declared_imports: tuple[str, ...] = ()


class SandboxSelfTestSuite(unittest.TestCase):
    """Comprehensive unit and isolation test suite for backend/sandbox.py (Section 5)."""

    def test_01_valid_generated_python_code(self) -> None:
        code = (
            "import math\n"
            "import re\n"
            "def _helper(val: int) -> int:\n"
            "    return int(math.sqrt(val))\n"
            "def run(input: dict, config: dict) -> dict:\n"
            "    raw = int(input.get('amount', 16))\n"
            "    return {'root': _helper(raw), 'clean': re.sub(r'\\s+', ' ', str(input.get('tag', '')))}\n"
        )
        ast_ok, sig_ok, err = SandboxVerifier.lint_ast_and_signature(code)
        self.assertTrue(ast_ok, f"Expected ast_ok=True, got error: {err}")
        self.assertTrue(sig_ok, f"Expected sig_ok=True, got error: {err}")
        self.assertEqual(err, "")

    def test_02_invalid_python_syntax(self) -> None:
        bad_syntax = "def run(input: dict, config: dict) -> dict:\n    return {'unclosed': [\n"
        ast_ok, sig_ok, err = SandboxVerifier.lint_ast_and_signature(bad_syntax)
        self.assertFalse(ast_ok)
        self.assertFalse(sig_ok)
        self.assertIn("SyntaxError", err)

    def test_03_disallowed_imports(self) -> None:
        for bad_imp in (
            "import os\ndef run(input: dict, config: dict) -> dict:\n    return {}\n",
            "import socket\ndef run(input: dict, config: dict) -> dict:\n    return {}\n",
            "from subprocess import Popen\ndef run(input: dict, config: dict) -> dict:\n    return {}\n",
            "from . import helper\ndef run(input: dict, config: dict) -> dict:\n    return {}\n",
        ):
            ast_ok, sig_ok, err = SandboxVerifier.lint_ast_and_signature(bad_imp)
            self.assertFalse(ast_ok, f"Disallowed import not blocked: {bad_imp}")
            self.assertFalse(sig_ok)
            self.assertIn("import", err.lower())

    def test_04_forbidden_function_calls_and_dunders(self) -> None:
        for bad_code in (
            "def run(input: dict, config: dict) -> dict:\n    return {'x': input('prompt')}\n",
            "def run(input: dict, config: dict) -> dict:\n    return {'x': eval('1+1')}\n",
            "def run(input: dict, config: dict) -> dict:\n    open('/etc/passwd')\n    return {}\n",
            "def run(input: dict, config: dict) -> dict:\n    return {'x': input.__class__}\n",
            "x = input\ndef run(input: dict, config: dict) -> dict:\n    return {}\n",
        ):
            ast_ok, _, err = SandboxVerifier.lint_ast_and_signature(bad_code)
            self.assertFalse(ast_ok, f"Forbidden call/dunder not blocked: {bad_code}")
            self.assertTrue(len(err) > 0)

    def test_05_invalid_generated_component_signature(self) -> None:
        for bad_sig in (
            "def wrong_name(input: dict, config: dict) -> dict:\n    return {}\n",
            "def run(data: dict, cfg: dict) -> dict:\n    return {}\n",
            "def run(input: dict) -> dict:\n    return {}\n",
            "async def run(input: dict, config: dict) -> dict:\n    return {}\n",
            "def run(input: dict, config: dict, *args) -> dict:\n    return {}\n",
            "def run(input: dict, config: dict) -> list:\n    return []\n",
        ):
            ast_ok, sig_ok, err = SandboxVerifier.lint_ast_and_signature(bad_sig)
            self.assertTrue(ast_ok)
            self.assertFalse(sig_ok, f"Invalid signature was not rejected: {bad_sig}")
            self.assertTrue(len(err) > 0)

    def test_06_valid_json_schema_output(self) -> None:
        schema = {
            "type": "object",
            "required": ["decision", "eligible", "count", "ratio", "tags", "meta"],
            "properties": {
                "decision": {"type": "string", "enum": ["approve", "reject"]},
                "eligible": {"type": "boolean"},
                "count": {"type": "integer"},
                "ratio": {"type": "number"},
                "tags": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                "meta": {
                    "type": "object",
                    "required": ["tier"],
                    "properties": {"tier": {"type": "string"}},
                },
            },
        }
        valid_out = {
            "decision": "approve",
            "eligible": True,
            "count": 3,
            "ratio": 0.75,
            "tags": ["vip"],
            "meta": {"tier": "gold"},
        }
        errs = SandboxVerifier.validate_output_against_schema(valid_out, schema)
        self.assertEqual(errs, [])

    def test_07_invalid_json_schema_output(self) -> None:
        schema = {
            "type": "object",
            "required": ["decision", "count", "meta"],
            "properties": {
                "decision": {"type": "string"},
                "count": {"type": "integer"},
                "meta": {
                    "type": "object",
                    "required": ["tier"],
                    "properties": {"tier": {"type": "string"}},
                },
            },
        }
        # count is boolean True (must not pass integer check!), meta.tier is missing
        invalid_out = {"decision": "approve", "count": True, "meta": {}}
        errs = SandboxVerifier.validate_output_against_schema(invalid_out, schema)
        self.assertTrue(any("expected integer" in e for e in errs))
        self.assertTrue(any("meta.tier" in e for e in errs))

    def test_08_nested_expected_value_comparison(self) -> None:
        actual = {
            "decision": "approve_refund",
            "citation": "Full refunds are granted within 30 calendar days of purchase.",
            "nested": {
                "flag": True,
                "counts": [10, 20, {"sub": 3.1415926}],
            },
            "extra_key": "allowed_in_actual",
        }
        expected_ok = {
            "decision": "approve_refund",
            "citation": "30 calendar days",
            "nested": {
                "flag": True,
                "counts": [10, 20, {"sub": 3.1415927}],
            },
        }
        self.assertTrue(SandboxVerifier.value_matches_expected(actual, expected_ok))

        # Bool True must not match int 1
        self.assertFalse(
            SandboxVerifier.value_matches_expected(
                actual, {"nested": {"flag": 1}}
            )
        )
        # List length mismatch or nested element mismatch must fail
        self.assertFalse(
            SandboxVerifier.value_matches_expected(
                actual, {"nested": {"counts": [10, 20]}}
            )
        )
        self.assertFalse(
            SandboxVerifier.value_matches_expected(
                actual, {"nested": {"counts": [10, 99, {"sub": 3.1415926}]}}
            )
        )

    def test_09_docker_execution_simulated_and_real(self) -> None:
        code = (
            "def run(input: dict, config: dict) -> dict:\n"
            "    days = int(input.get('days', 0))\n"
            "    limit = int(config.get('limit', 30))\n"
            "    return {'eligible': days <= limit}\n"
        )
        vec = TestVector(
            vector_id="v1",
            input_payload={"days": 15},
            config_payload={"limit": 30},
            expected_subset={"eligible": True},
        )

        # 9a. Simulated Docker runner verifying flags & isolated execution
        sim_verifier = SandboxVerifier(
            SandboxConfig(), docker_runner_override=_simulated_docker_runner_for_tests
        )
        ok, mode, results, err = sim_verifier.execute_in_sandbox(code, [vec])
        self.assertTrue(ok, f"Simulated Docker execution failed: {err}")
        self.assertEqual(mode, "docker")
        self.assertEqual(results, [{"vector_id": "v1", "output": {"eligible": True}}])

        # 9b. Real Docker integration check (only marked passed if real Docker daemon is running)
        real_verifier = SandboxVerifier(SandboxConfig())
        if real_verifier._docker_available():
            ok_real, mode_real, res_real, err_real = real_verifier.execute_in_sandbox(
                code, [vec]
            )
            self.assertTrue(ok_real, f"Real Docker execution failed: {err_real}")
            self.assertEqual(mode_real, "docker")
            self.assertEqual(
                res_real, [{"vector_id": "v1", "output": {"eligible": True}}]
            )

    def test_10_docker_timeout(self) -> None:
        def _timeout_runner(
            cmd: list[str], stdin_bytes: bytes, timeout_s: int
        ) -> subprocess.CompletedProcess[bytes]:
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout_s)

        verifier = SandboxVerifier(
            SandboxConfig(sandbox_timeout_seconds=2),
            docker_runner_override=_timeout_runner,
        )
        vec = TestVector(vector_id="v_timeout", input_payload={"x": 1})
        ok, mode, results, err = verifier.execute_in_sandbox(
            "def run(input: dict, config: dict) -> dict:\n    return {}\n", [vec]
        )
        self.assertFalse(ok)
        self.assertEqual(mode, "docker")
        self.assertEqual(results, [])
        self.assertIn("timed out after 2s", err)

    def test_11_docker_unavailable_with_fallback_disabled(self) -> None:
        verifier = SandboxVerifier(
            SandboxConfig(
                prefer_docker_sandbox=True, allow_subprocess_dev_fallback=False
            )
        )
        verifier._docker_available = lambda: False  # type: ignore[method-assign]
        vec = TestVector(vector_id="v_blocked", input_payload={"x": 1})
        ok, mode, results, err = verifier.execute_in_sandbox(
            "def run(input: dict, config: dict) -> dict:\n    return {}\n", [vec]
        )
        self.assertFalse(ok)
        self.assertEqual(mode, "blocked")
        self.assertEqual(results, [])
        self.assertIn("failing closed", err)

    def test_12_hidden_test_input_confidentiality(self) -> None:
        secret_hidden_input = "TOP_SECRET_HIDDEN_PATIENT_SSN_999_88_7777"
        secret_hidden_expected = "TOP_SECRET_EXPECTED_DIAGNOSIS_CODE_XYZ987"

        captured_stdin: list[bytes] = []

        def _inspecting_runner(
            cmd: list[str], stdin_bytes: bytes, timeout_s: int
        ) -> subprocess.CompletedProcess[bytes]:
            captured_stdin.append(stdin_bytes)
            return _simulated_docker_runner_for_tests(cmd, stdin_bytes, timeout_s)

        verifier = SandboxVerifier(
            SandboxConfig(), docker_runner_override=_inspecting_runner
        )
        vis_vec = TestVector(
            vector_id="vec_vis_1",
            input_payload={"query": "public_query"},
            expected_subset={"answer": "public_answer"},
            visibility="visible",
        )
        hid_vec = TestVector(
            vector_id="vec_hid_1",
            input_payload={"query": secret_hidden_input},
            expected_subset={"answer": secret_hidden_expected},
            visibility="hidden",
        )

        # Code that attempts to print input to stdout and raise an exception echoing the secret input
        exfiltration_code = (
            "def run(input: dict, config: dict) -> dict:\n"
            "    q = str(input.get('query', ''))\n"
            "    print('TRY_LEAK_STDOUT:', q)\n"
            "    if 'SSN' in q:\n"
            "        raise ValueError(f'Exfiltrating hidden input: {q}')\n"
            "    return {'answer': 'public_answer'}\n"
        )
        task = _DummyCodeGenTask(
            output_schema={
                "type": "object",
                "required": ["answer"],
                "properties": {"answer": {"type": "string"}},
            },
            visible_test_vectors=(vis_vec,),
        )
        res = _DummyCodeGenResult(source_code=exfiltration_code)
        report = verifier.verify_generated_component(
            task=task, result=res, hidden_vectors=[hid_vec]
        )

        self.assertFalse(report.passed)
        # 1. Verify expected_subset and visibility were stripped from stdin sent to sandbox worker
        self.assertEqual(len(captured_stdin), 1)
        stdin_str = captured_stdin[0].decode("utf-8")
        self.assertNotIn(secret_hidden_expected, stdin_str)
        self.assertNotIn("expected_subset", stdin_str)
        self.assertNotIn("visibility", stdin_str)

        # 2. Verify neither secret_hidden_input nor secret_hidden_expected appears in report
        report_json = json.dumps(report.model_dump(mode="json"))
        self.assertNotIn(secret_hidden_input, report_json)
        self.assertNotIn(secret_hidden_expected, report_json)

    def test_13_sanitized_failure_reports(self) -> None:
        verifier = SandboxVerifier(
            SandboxConfig(),
            docker_runner_override=_simulated_docker_runner_for_tests,
        )
        vis_vec = TestVector(
            vector_id="vec_vis_1",
            input_payload={"val": 10},
            expected_subset={"result": "ok_vis"},
            visibility="visible",
        )
        hid_vec = TestVector(
            vector_id="vec_hid_99",
            input_payload={"val": 999999},
            expected_subset={"result": "CONFIDENTIAL_HIDDEN_EXPECTED_STRING"},
            visibility="hidden",
        )
        # Code passes visible vector, but returns wrong value on hidden vector
        code = (
            "def run(input: dict, config: dict) -> dict:\n"
            "    v = int(input.get('val', 0))\n"
            "    return {'result': 'ok_vis' if v == 10 else 'wrong_hidden_actual_value'}\n"
        )
        task = _DummyCodeGenTask(
            output_schema={
                "type": "object",
                "required": ["result"],
                "properties": {"result": {"type": "string"}},
            },
            visible_test_vectors=(vis_vec,),
        )
        report = verifier.verify_generated_component(
            task=task,
            result=_DummyCodeGenResult(source_code=code),
            hidden_vectors=[hid_vec],
        )
        self.assertFalse(report.passed)
        self.assertTrue(report.stage_results["4_visible_vectors"])
        self.assertFalse(report.stage_results["5_hidden_vectors"])
        # Only sanitized identifier 'hidden_vector:vec_hid_99' is returned
        self.assertEqual(report.failing_vectors_sanitized, ("hidden_vector:vec_hid_99",))
        self.assertNotIn("CONFIDENTIAL_HIDDEN_EXPECTED_STRING", report.error_summary)
        self.assertNotIn("wrong_hidden_actual_value", report.error_summary)
        self.assertNotIn("999999", report.error_summary)

    def test_14_complete_verify_generated_component_workflow(self) -> None:
        verifier = SandboxVerifier(
            SandboxConfig(),
            docker_runner_override=_simulated_docker_runner_for_tests,
        )
        vis_vec = TestVector(
            vector_id="vec_vis_1",
            input_payload={"days_elapsed": 12},
            expected_subset={"decision": "approve_refund"},
            visibility="visible",
        )
        hid_vec = TestVector(
            vector_id="vec_hid_1",
            input_payload={"days_elapsed": 45},
            expected_subset={"decision": "reject_refund"},
            visibility="hidden",
        )
        task = _DummyCodeGenTask(
            component_id="fn.sla_tier_calc",
            version="1.0.0",
            output_schema={
                "type": "object",
                "required": ["decision"],
                "properties": {"decision": {"type": "string"}},
            },
            visible_test_vectors=(vis_vec,),
        )

        # 14a. Complete passing workflow across all 6 stages
        good_code = (
            "import math\n"
            "def run(input: dict, config: dict) -> dict:\n"
            "    days = int(input.get('days_elapsed', 0))\n"
            "    return {'decision': 'approve_refund' if days <= 30 else 'reject_refund'}\n"
        )
        rep_ok = verifier.verify_generated_component(
            task=task,
            result=_DummyCodeGenResult(
                source_code=good_code, declared_imports=("math",)
            ),
            hidden_vectors=[hid_vec],
        )
        self.assertTrue(rep_ok.passed, f"Expected pass, got: {rep_ok.error_summary}")
        self.assertTrue(all(rep_ok.stage_results.values()))
        self.assertEqual(rep_ok.failing_vectors_sanitized, ())

        # 14b. Stage 1 secret-leak rejection
        secret_code = (
            "def run(input: dict, config: dict) -> dict:\n"
            "    key = 'sk-1234567890abcdefghijklmnop'\n"
            "    return {'decision': 'approve_refund'}\n"
        )
        rep_sec = verifier.verify_generated_component(
            task=task,
            result=_DummyCodeGenResult(source_code=secret_code),
            hidden_vectors=[hid_vec],
        )
        self.assertFalse(rep_sec.passed)
        self.assertFalse(rep_sec.stage_results["1_size_path_secrets"])

        # 14c. Non-deterministic function rejected in sandbox double-run check
        nondet_code = (
            "import datetime\n"
            "_counter = []\n"
            "def run(input: dict, config: dict) -> dict:\n"
            "    _counter.append(1)\n"
            "    return {'decision': str(len(_counter))}\n"
        )
        rep_nondet = verifier.verify_generated_component(
            task=task,
            result=_DummyCodeGenResult(
                source_code=nondet_code, declared_imports=("datetime",)
            ),
            hidden_vectors=[hid_vec],
        )
        self.assertFalse(rep_nondet.passed)
        self.assertIn("NonDeterministicOutputError", rep_nondet.error_summary)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AdaptOS Sandbox Verifier & Self-Test Suite")
    parser.add_argument(
        "--self-test", action="store_true", help="Run the 14-test Sandbox unittest suite"
    )
    _ = parser.parse_args(list(argv) if argv is not None else None)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SandboxSelfTestSuite)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())