"""Registro de auditoría de sólo anexado con encadenamiento de hashes.

Cada entrada incluye el hash de la anterior, de modo que cualquier
modificación del archivo SQLite fuera de la aplicación es detectable con
``verify()``. Las sentencias UPDATE/DELETE están bloqueadas por triggers.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from netcommand.common.util import dumps, now
from netcommand.server.db import Database

log = logging.getLogger("netcommand.audit")

GENESIS = "0" * 64
_SENSITIVE = {"password", "new_password", "current_password", "code", "token", "data_b64", "secret",
              "totp", "pairing_code"}


def redact(details: dict[str, Any] | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in (details or {}).items():
        if k in _SENSITIVE:
            out[k] = "***"
        elif isinstance(v, dict):
            out[k] = redact(v)
        elif isinstance(v, str) and len(v) > 500:
            out[k] = v[:500] + "…"
        else:
            out[k] = v
    return out


def _entry_hash(prev: str, ts: float, actor: str, actor_ip: str | None, action: str, target: str,
                details: str, result: str) -> str:
    material = "\x1f".join([prev, repr(ts), actor, actor_ip or "", action, target, details, result])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, db: Database):
        self.db = db

    def record(self, actor: str, action: str, target: str = "", details: dict[str, Any] | None = None,
               result: str = "ok", actor_ip: str | None = None) -> int:
        details_s = dumps(redact(details))
        with self.db.tx():
            prev = self.db.scalar("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1") or GENESIS
            ts = now()
            h = _entry_hash(prev, ts, actor, actor_ip, action, target, details_s, result)
            cur = self.db.execute(
                "INSERT INTO audit_log (ts, actor, actor_ip, action, target, details, result, prev_hash, hash)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (ts, actor, actor_ip, action, target, details_s, result, prev, h),
            )
        log.info("AUDITORÍA actor=%s acción=%s objetivo=%s resultado=%s", actor, action, target, result)
        return int(cur.lastrowid)

    def verify(self) -> dict[str, Any]:
        prev = GENESIS
        count = 0
        for row in self.db.query("SELECT * FROM audit_log ORDER BY id"):
            expected = _entry_hash(prev, row["ts"], row["actor"], row["actor_ip"], row["action"],
                                   row["target"], row["details"], row["result"])
            if row["prev_hash"] != prev or row["hash"] != expected:
                return {"ok": False, "checked": count, "broken_at": row["id"],
                        "message": f"La cadena de auditoría está rota en la entrada {row['id']}"}
            prev = row["hash"]
            count += 1
        return {"ok": True, "checked": count, "broken_at": None,
                "message": f"Cadena íntegra ({count} entradas verificadas)"}

    def search(self, actor: str | None = None, action: str | None = None, target: str | None = None,
               since: float | None = None, until: float | None = None, limit: int = 500,
               offset: int = 0) -> list[dict[str, Any]]:
        where, params = [], []
        if actor:
            where.append("actor LIKE ?")
            params.append(f"%{actor}%")
        if action:
            where.append("action LIKE ?")
            params.append(f"%{action}%")
        if target:
            where.append("target LIKE ?")
            params.append(f"%{target}%")
        if since:
            where.append("ts >= ?")
            params.append(since)
        if until:
            where.append("ts <= ?")
            params.append(until)
        sql = "SELECT id, ts, actor, actor_ip, action, target, details, result FROM audit_log"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params += [min(limit, 5000), offset]
        return self.db.query(sql, params)
