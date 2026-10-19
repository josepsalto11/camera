"""Acceso a SQLite y ejecución de migraciones versionadas."""

from __future__ import annotations

import logging
import re
import sqlite3
import threading
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).with_name("migrations")
_MIGRATION_RE = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")


class Database:
    """Conexión única protegida por un cerrojo.

    SQLite en modo WAL es más que suficiente para el volumen de una consola
    de red local (cientos de equipos). Todas las escrituras pasan por el
    mismo cerrojo, lo que evita errores ``database is locked``.
    """

    def __init__(self, path: Path | str):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._depth = 0
        with self._lock:
            if self.path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.execute("PRAGMA synchronous=NORMAL")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def tx(self) -> Iterator[Database]:
        with self._lock:
            outer = self._depth == 0
            if outer:
                self._conn.execute("BEGIN IMMEDIATE")
            self._depth += 1
            try:
                yield self
            except BaseException:
                self._depth -= 1
                if outer:
                    self._conn.execute("ROLLBACK")
                raise
            else:
                self._depth -= 1
                if outer:
                    self._conn.execute("COMMIT")

    def execute(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, params)

    def executemany(self, sql: str, seq: list[Sequence[Any]]) -> None:
        with self._lock:
            self._conn.executemany(sql, seq)

    def query(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    def one(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
            return dict(row) if row else None

    def scalar(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> Any:
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
            return row[0] if row else None

    # ------------------------------------------------------------------
    def schema_version(self) -> int:
        with self._lock:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT, applied_at REAL)"
            )
            v = self._conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
            return int(v or 0)

    def migrate(self, migrations_dir: Path = MIGRATIONS_DIR) -> list[str]:
        applied: list[str] = []
        current = self.schema_version()
        files = sorted(p for p in migrations_dir.iterdir() if _MIGRATION_RE.match(p.name))
        for f in files:
            version = int(f.name[:4])
            if version <= current:
                continue
            sql = f.read_text(encoding="utf-8")
            log.info("Aplicando migración %s", f.name)
            with self._lock:
                try:
                    self._conn.execute("BEGIN IMMEDIATE")
                    for stmt in _split_sql(sql):
                        self._conn.execute(stmt)
                    self._conn.execute(
                        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                        (version, f.name, time.time()),
                    )
                    self._conn.execute("COMMIT")
                except Exception:
                    self._conn.execute("ROLLBACK")
                    raise
            applied.append(f.name)
        return applied

    def integrity_check(self) -> str:
        return str(self.scalar("PRAGMA integrity_check"))


def _split_sql(script: str) -> list[str]:
    """Divide un script en sentencias respetando bloques BEGIN...END de triggers."""
    statements: list[str] = []
    buf: list[str] = []
    for line in script.splitlines():
        stripped = line.strip()
        if not buf and (not stripped or stripped.startswith("--")):
            continue
        buf.append(line)
        candidate = "\n".join(buf)
        if sqlite3.complete_statement(candidate):
            statements.append(candidate.strip())
            buf = []
    if buf and "\n".join(buf).strip():
        statements.append("\n".join(buf).strip())
    return statements
