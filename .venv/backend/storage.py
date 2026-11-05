"""Agnos AI storage infrastructure scaffold.

Planner/Policy decides required resources. This module provides connections and
basic operations. Keep the evaluator vault and signing key outside this service.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterator, Literal, Mapping, Sequence


class StorageError(RuntimeError):
    pass


class UnsafePathError(StorageError):
    pass


class IntegrityError(StorageError):
    pass


@dataclass(frozen=True)
class StorageConfig:
    data_root: Path
    busy_timeout_ms: int = 10_000
    enable_chroma: bool = True

    @property
    def factory_db_path(self) -> Path:
        return self.data_root / "factory.db"

    @property
    def blob_root(self) -> Path:
        return self.data_root / "blobs"

    @property
    def apps_root(self) -> Path:
        return self.data_root / "apps"


class StorageService:
    """Central factory-side access to metadata DB, blobs, app DBs and Chroma."""

    _APP_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
    _WINDOWS_RESERVED_NAMES = frozenset(
        {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
    )
    _FTS_TABLE = "documents_fts"
    _MAX_FTS_TERMS = 32
    _MAX_FTS_DOC_BYTES = 10_000_000
    _MAX_DOC_ID_CHARS = 256

    def __init__(self, config: StorageConfig) -> None:
        self.config = config
        self._initialized = False

    def initialize(self) -> None:
        self.config.data_root.mkdir(parents=True, exist_ok=True)
        self.config.blob_root.mkdir(parents=True, exist_ok=True)
        self.config.apps_root.mkdir(parents=True, exist_ok=True)
        if self.config.enable_chroma:
            (self.config.data_root / "chroma").mkdir(parents=True, exist_ok=True)

        with self.get_factory_db() as conn:
            conn.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS storage_operations (
                    operation_id TEXT PRIMARY KEY,
                    operation_type TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL CHECK(status IN
                        ('planned','running','ready','failed')),
                    details_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS storage_resources (
                    resource_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    app_id TEXT NOT NULL,
                    resource_name TEXT NOT NULL,
                    resource_kind TEXT NOT NULL,
                    backend TEXT NOT NULL,
                    relative_path TEXT,
                    schema_version TEXT,
                    status TEXT NOT NULL CHECK(status IN
                        ('planned','ready','deleting','failed')),
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(app_id, resource_kind, resource_name)
                );
                CREATE INDEX IF NOT EXISTS idx_storage_resources_project
                    ON storage_resources(project_id);
                CREATE INDEX IF NOT EXISTS idx_storage_resources_app
                    ON storage_resources(app_id);
            """)
        self._initialized = True

    @contextmanager
    def get_factory_db(self) -> Iterator[sqlite3.Connection]:
        self.config.data_root.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(
            self.config.factory_db_path,
            timeout=self.config.busy_timeout_ms / 1000,
            isolation_level=None,
        )
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={int(self.config.busy_timeout_ms)}")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
        finally:
            conn.close()

    def get_checkpoint_db_path(self) -> Path:
        """Path only: the workflow/checkpoint library owns its own schema."""
        directory = self.config.data_root / "checkpoints"
        directory.mkdir(parents=True, exist_ok=True)
        return directory / "checkpoints.db"

    def put_blob(self, content: bytes) -> str:
        """Atomically store bytes by SHA-256; return the digest."""
        if not isinstance(content, bytes):
            raise TypeError("content must be bytes")
        digest = hashlib.sha256(content).hexdigest()
        destination = self._blob_path(digest)
        destination.parent.mkdir(parents=True, exist_ok=True)

        if destination.exists():
            self.verify_blob(digest)
            return digest

        fd, temp_name = tempfile.mkstemp(prefix=".tmp-", dir=str(destination.parent))
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.replace(temp_path, destination)
            except OSError:
                if not destination.exists():
                    raise
            self.verify_blob(digest)
            return digest
        finally:
            temp_path.unlink(missing_ok=True)

    def get_blob(self, sha256: str) -> bytes:
        self._validate_sha256(sha256)
        path = self._blob_path(sha256)
        try:
            content = path.read_bytes()
        except FileNotFoundError as exc:
            raise StorageError(f"Blob not found: {sha256}") from exc
        if hashlib.sha256(content).hexdigest() != sha256:
            raise IntegrityError(f"Blob hash mismatch: {sha256}")
        return content

    def verify_blob(self, sha256: str) -> bool:
        self.get_blob(sha256)
        return True

    def _blob_path(self, sha256: str) -> Path:
        self._validate_sha256(sha256)
        return self.config.blob_root / sha256[:2] / sha256[2:]

    @staticmethod
    def _validate_sha256(value: str) -> None:
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("sha256 must be a 64-character lowercase hexadecimal digest")

    def provision_app_storage(self, manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Provision only explicitly declared resources; repeated calls are idempotent."""
        self._require_initialized()
        if not isinstance(manifest, Mapping):
            raise StorageError("manifest must be an object")
        project_id = self._required_text(manifest, "project_id")
        app_id = self._required_text(manifest, "app_id")
        resources = manifest.get("resources", [])
        if not isinstance(resources, Sequence) or isinstance(resources, (str, bytes)):
            raise StorageError("manifest.resources must be a list")
        app_root = self._app_root(app_id)
        output: list[dict[str, Any]] = []

        # Validate the entire manifest before touching the filesystem.
        planned: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for item in resources:
            if not isinstance(item, Mapping):
                raise StorageError("Each resource must be an object")
            name = self._required_text(item, "name")
            kind = self._required_text(item, "kind")
            backend = self._required_text(item, "backend")
            rel = item.get("rel_path")
            schema_version = item.get("schema_version")
            if (kind, name) in seen:
                raise StorageError(f"Duplicate resource in manifest: {kind}/{name}")
            seen.add((kind, name))
            if backend in {"sqlite", "fts5", "bm25"} and not isinstance(rel, str):
                raise StorageError(f"Resource {name!r} requires rel_path")
            if backend in {"chroma", "chroma_db"}:
                if not self.config.enable_chroma:
                    raise StorageError("ChromaDB is disabled")
                if rel not in (None, "chroma"):
                    raise StorageError("Chroma resource path must be 'chroma'")
                rel = "chroma"
            if backend not in {"sqlite", "fts5", "bm25", "chroma", "chroma_db", "blob"}:
                raise StorageError(f"Unsupported storage backend: {backend}")
            path = self._safe_app_path(app_root, rel) if rel is not None else None
            planned.append({"name": name, "kind": kind, "backend": backend,
                            "rel": rel, "path": path,
                            "schema_version": str(schema_version) if schema_version is not None else None})

        app_root.mkdir(parents=True, exist_ok=True)
        for item in planned:
            name, kind, backend = item["name"], item["kind"], item["backend"]
            rel, path, schema_version = item["rel"], item["path"], item["schema_version"]
            resource_id = hashlib.sha256(f"{project_id}\0{app_id}\0{kind}\0{name}".encode()).hexdigest()
            idem = hashlib.sha256(canonical_json({"project_id": project_id, "app_id": app_id,
                "name": name, "kind": kind, "backend": backend, "rel_path": rel,
                "schema_version": schema_version}).encode("utf-8")).hexdigest()
            with self.get_factory_db() as conn:
                conn.execute("BEGIN IMMEDIATE")
                existing = conn.execute("""SELECT project_id, backend, relative_path, schema_version, status
                    FROM storage_resources WHERE app_id=? AND resource_kind=? AND resource_name=?""",
                    (app_id, kind, name)).fetchone()
                expected = (project_id, backend, str(rel) if rel is not None else None, schema_version)
                if existing:
                    actual = (existing["project_id"], existing["backend"], existing["relative_path"], existing["schema_version"])
                    if actual != expected:
                        conn.rollback()
                        raise StorageError(f"Resource conflict for {app_id}/{kind}/{name}: existing metadata differs")
                    if existing["status"] == "ready" and self._resource_exists(path, backend):
                        conn.commit()
                        output.append({"resource_id": resource_id, "project_id": project_id, "app_id": app_id,
                            "name": name, "kind": kind, "backend": backend,
                            "path": str(path) if path else None, "status": "ready"})
                        continue
                    conn.execute("UPDATE storage_resources SET status='planned' WHERE app_id=? AND resource_kind=? AND resource_name=?",
                                 (app_id, kind, name))
                else:
                    conn.execute("""INSERT INTO storage_resources
                        (resource_id,project_id,app_id,resource_name,resource_kind,backend,relative_path,schema_version,status)
                        VALUES (?,?,?,?,?,?,?,?, 'planned')""",
                        (resource_id, project_id, app_id, name, kind, backend, str(rel) if rel is not None else None, schema_version))
                conn.execute("""INSERT INTO storage_operations
                    (operation_id,operation_type,idempotency_key,status,details_json)
                    VALUES (?,?,?,?,?) ON CONFLICT(idempotency_key) DO UPDATE SET
                    status=CASE WHEN storage_operations.status='ready' THEN 'ready' ELSE 'planned' END,
                    updated_at=CURRENT_TIMESTAMP""",
                    (idem, "provision_resource", idem, "planned", canonical_json({"app_id": app_id, "name": name, "backend": backend, "rel_path": rel})))
                conn.commit()

            try:
                if backend == "sqlite":
                    assert path is not None
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with sqlite3.connect(path, timeout=self.config.busy_timeout_ms / 1000) as db:
                        db.execute("PRAGMA foreign_keys=ON")
                        db.execute("PRAGMA journal_mode=WAL")
                        db.execute(f"PRAGMA busy_timeout={int(self.config.busy_timeout_ms)}")
                elif backend in {"fts5", "bm25"}:
                    assert path is not None
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with sqlite3.connect(path, timeout=self.config.busy_timeout_ms / 1000) as db:
                        db.execute("PRAGMA foreign_keys=ON")
                        db.execute("PRAGMA journal_mode=WAL")
                        db.execute(f"PRAGMA busy_timeout={int(self.config.busy_timeout_ms)}")
                        db.execute(f"CREATE VIRTUAL TABLE IF NOT EXISTS {self._FTS_TABLE} USING fts5(doc_id UNINDEXED, content, tokenize='porter ascii')")
                elif backend in {"chroma", "chroma_db"}:
                    assert path is not None
                    path.mkdir(parents=True, exist_ok=True)
                # blob resources use the global content-addressed blob store.
                with self.get_factory_db() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    conn.execute("UPDATE storage_resources SET status='ready' WHERE app_id=? AND resource_kind=? AND resource_name=?",
                                 (app_id, kind, name))
                    conn.execute("UPDATE storage_operations SET status='ready', updated_at=CURRENT_TIMESTAMP WHERE idempotency_key=?", (idem,))
                    conn.commit()
            except Exception as exc:
                with self.get_factory_db() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    conn.execute("UPDATE storage_resources SET status='failed' WHERE app_id=? AND resource_kind=? AND resource_name=?",
                                 (app_id, kind, name))
                    conn.execute("UPDATE storage_operations SET status='failed', details_json=?, updated_at=CURRENT_TIMESTAMP WHERE idempotency_key=?",
                                 (canonical_json({"error": str(exc)[:500]}), idem))
                    conn.commit()
                raise
            output.append({"resource_id": resource_id, "project_id": project_id, "app_id": app_id,
                "name": name, "kind": kind, "backend": backend, "path": str(path) if path else None, "status": "ready"})
        return output

    @staticmethod
    def _resource_exists(path: Path | None, backend: str) -> bool:
        if backend == "blob":
            return True
        return bool(path and (path.is_dir() if backend in {"chroma", "chroma_db"} else path.is_file()))

    def _require_resource(self, app_id: str, relative_path: str, backends: set[str]) -> sqlite3.Row:
        with self.get_factory_db() as conn:
            rows = conn.execute("""SELECT * FROM storage_resources WHERE app_id=? AND status='ready'
                AND backend IN ({})""".format(",".join("?" for _ in backends)),
                (app_id, *sorted(backends))).fetchall()
        normalized = PurePosixPath(relative_path).as_posix()
        for row in rows:
            if row["relative_path"] == normalized:
                return row
        raise StorageError(f"Resource is not approved and ready: {app_id}/{relative_path}")

    def get_app_db(self, app_id: str, relative_path: str = "app.db", *, read_only: bool = False) -> sqlite3.Connection:
        """Open only a SQLite resource declared in the ready storage manifest."""
        self._require_initialized()
        root = self._provisioned_root(app_id)
        path = self._safe_app_path(root, relative_path)
        if path.relative_to(root).parts[0].casefold() == "chroma":
            raise UnsafePathError("ChromaDB-owned paths cannot be opened as SQLite")
        self._require_resource(app_id, relative_path, {"sqlite", "fts5", "bm25"})
        timeout = int(self.config.busy_timeout_ms)
        if read_only:
            if not path.is_file():
                raise StorageError(f"Database does not exist: {relative_path!r}")
            conn = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=timeout / 1000)
        else:
            if not path.is_file():
                raise StorageError(f"Database resource has not been provisioned: {relative_path!r}")
            conn = sqlite3.connect(path, timeout=timeout / 1000)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute(f"PRAGMA busy_timeout={timeout}")
            conn.execute("PRAGMA foreign_keys=ON")
            if read_only:
                conn.execute("PRAGMA query_only=ON")
        except BaseException:
            conn.close()
            raise
        return conn
    def get_chroma_collection(self, app_id: str, collection_name: str, *, metadata: Mapping[str, Any] | None = None) -> Any:
        self._require_initialized()
        if not self.config.enable_chroma:
            raise StorageError("ChromaDB is disabled")
        if not isinstance(collection_name, str) or not 3 <= len(collection_name) <= 512 or collection_name.strip() != collection_name:
            raise ValueError("collection_name must be trimmed and 3..512 characters")
        self._require_resource(app_id, "chroma", {"chroma", "chroma_db"})
        with self.get_factory_db() as conn:
            row = conn.execute("SELECT resource_name FROM storage_resources WHERE app_id=? AND backend IN ('chroma','chroma_db') AND relative_path='chroma' AND status='ready' AND resource_name=?",
                               (app_id, collection_name)).fetchone()
        if row is None:
            raise StorageError(f"Chroma collection is not approved: {collection_name}")
        try:
            import chromadb
            from chromadb.config import Settings
        except ImportError as exc:
            raise StorageError("Install optional dependency with: pip install chromadb") from exc
        root = self._provisioned_root(app_id)
        path = self._safe_app_path(root, "chroma")
        client = chromadb.PersistentClient(path=str(path), settings=Settings(anonymized_telemetry=False))
        return client.get_or_create_collection(name=collection_name, metadata=dict(metadata) if metadata else None)

    def add_fts5_document(self, app_id: str, doc_id: str, content: str, *, relative_path: str = "app.db") -> None:
        if not isinstance(doc_id, str) or not doc_id.strip() or len(doc_id) > self._MAX_DOC_ID_CHARS:
            raise ValueError(f"doc_id must be a non-empty string of at most {self._MAX_DOC_ID_CHARS} characters")
        if not isinstance(content, str) or len(content.encode("utf-8")) > self._MAX_FTS_DOC_BYTES:
            raise ValueError(f"content must be a string of at most {self._MAX_FTS_DOC_BYTES} bytes")
        conn = self.get_app_db(app_id, relative_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(f"DELETE FROM {self._FTS_TABLE} WHERE doc_id=?", (doc_id,))
            conn.execute(f"INSERT INTO {self._FTS_TABLE}(doc_id, content) VALUES (?, ?)", (doc_id, content))
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def search_fts5(self, app_id: str, query: str, *, limit: int = 5, relative_path: str = "app.db",
                    mode: Literal["any", "all"] = "any") -> list[dict[str, Any]]:
        expression = self._fts5_match_expression(query, mode)
        if not expression:
            return []
        conn = self.get_app_db(app_id, relative_path, read_only=True)
        try:
            try:
                rows = conn.execute(f"SELECT doc_id, content, bm25({self._FTS_TABLE}) AS score FROM {self._FTS_TABLE} WHERE {self._FTS_TABLE} MATCH ? ORDER BY score, doc_id LIMIT ?",
                                    (expression, max(1, min(int(limit), 100)))).fetchall()
            except sqlite3.OperationalError as exc:
                if "no such table" in str(exc).lower():
                    raise StorageError("FTS5 index has not been provisioned for this app") from exc
                raise
            return [dict(row) for row in rows]
        finally:
            conn.close()

    @classmethod
    def _fts5_match_expression(cls, query: str, mode: str) -> str:
        if not isinstance(query, str):
            raise ValueError("query must be a string")
        if mode not in ("any", "all"):
            raise ValueError("mode must be 'any' or 'all'")
        # Preserve contractions as one token while treating punctuation as separators.
        tokens = list(dict.fromkeys(re.findall(r"[\w]+(?:['’][\w]+)*", query)))[:cls._MAX_FTS_TERMS]
        return (" OR " if mode == "any" else " ").join(f'"{token.replace(chr(34), chr(34)*2)}"' for token in tokens)

    def _provisioned_root(self, app_id: str) -> Path:
        root = self._app_root(app_id)
        if not root.is_dir():
            raise StorageError(f"App storage has not been provisioned: {app_id!r}")
        return root

    def _app_root(self, app_id: str) -> Path:
        if (not isinstance(app_id, str) or not self._APP_ID_RE.fullmatch(app_id)
                or app_id in self._WINDOWS_RESERVED_NAMES):
            raise UnsafePathError("Invalid app_id")
        apps_root = Path(self.config.apps_root).resolve()
        root = (apps_root / app_id).resolve()
        if root.parent != apps_root or root.name != app_id:
            raise UnsafePathError("App root does not resolve to its own directory under apps_root")
        return root

    @classmethod
    def _safe_app_path(cls, root: Path, relative_path: str) -> Path:
        if not isinstance(relative_path, str) or not relative_path:
            raise UnsafePathError(f"Unsafe relative path: {relative_path!r}")
        posix, windows = PurePosixPath(relative_path), PureWindowsPath(relative_path)
        if (not posix.parts or posix.is_absolute() or ".." in posix.parts
                or relative_path != posix.as_posix() or "\\" in relative_path
                or "\0" in relative_path or ":" in relative_path or windows.is_absolute()
                or windows.drive or windows.root):
            raise UnsafePathError(f"Unsafe relative path: {relative_path!r}")
        for part in posix.parts:
            if part != part.rstrip(" .") or part.split(".", 1)[0].lower() in cls._WINDOWS_RESERVED_NAMES:
                raise UnsafePathError(f"Unsafe relative path: {relative_path!r}")
        resolved_root = root.resolve()
        path = resolved_root.joinpath(*posix.parts).resolve()
        try:
            path.relative_to(resolved_root)
        except ValueError as exc:
            raise UnsafePathError(f"Path escapes app root: {relative_path!r}") from exc
        if path == resolved_root:
            raise UnsafePathError("Path resolves to app root itself")
        return path

    @staticmethod
    def _required_text(data: Mapping[str, Any], key: str) -> str:
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            raise StorageError(f"manifest.{key} must be a non-empty string")
        return value.strip()

    def _require_initialized(self) -> None:
        if not self._initialized:
            raise StorageError("Call StorageService.initialize() first")


def canonical_json(value: Any) -> str:
    """Stable JSON text; UTF-8 encoding matches schemas.canonical_json byte-for-byte."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


if __name__ == "__main__":
    root = Path(os.environ.get("AGNOS_DATA_ROOT", "./agnos_data"))
    service = StorageService(StorageConfig(root))
    service.initialize()
    digest = service.put_blob(b"Agnos AI storage smoke test")
    assert service.get_blob(digest) == b"Agnos AI storage smoke test"
    service.provision_app_storage({"project_id": "smoke-project", "app_id": "smoke-app", "resources": [
        {"name": "app-db", "kind": "database", "backend": "fts5", "rel_path": "app.db", "schema_version": "1"}
    ]})
    service.add_fts5_document("smoke-app", "doc-1", "Refund requests are accepted within 30 days.")
    hits = service.search_fts5("smoke-app", "can't get a refund?")
    assert [hit["doc_id"] for hit in hits] == ["doc-1"], hits
    try:
        service.get_app_db("smoke-app", "unauthorized.db")
    except StorageError:
        pass
    else:
        raise AssertionError("unapproved database access was not rejected")
    print(f"Storage initialized: {root.resolve()}")
    print(f"Factory DB: {service.config.factory_db_path.resolve()}")
    print(f"Blob SHA-256 smoke test: {digest}")
    print("Manifest provisioning + FTS5 + unauthorized-access smoke tests: ok")