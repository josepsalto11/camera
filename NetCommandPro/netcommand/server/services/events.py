"""Bus de eventos en proceso: persiste eventos y los difunde a las consolas."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from netcommand.common.util import dumps, now
from netcommand.server.db import Database

log = logging.getLogger(__name__)


class EventBus:
    def __init__(self, db: Database):
        self.db = db
        self._subscribers: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def publish(self, topic: str, payload: dict[str, Any]) -> None:
        """Difunde un mensaje en vivo (no se persiste)."""
        msg = {"topic": topic, "ts": now(), "data": payload}
        for q in list(self._subscribers):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                # Consola lenta: se descarta el mensaje más antiguo para no bloquear el servidor.
                try:
                    q.get_nowait()
                    q.put_nowait(msg)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass

    def event(self, kind: str, message: str, severity: str = "info", device_id: str | None = None,
              data: dict[str, Any] | None = None) -> int:
        """Registra un evento histórico y lo difunde."""
        ts = now()
        cur = self.db.execute(
            "INSERT INTO events (ts, kind, severity, device_id, message, data) VALUES (?, ?, ?, ?, ?, ?)",
            (ts, kind, severity, device_id, message, dumps(data or {})),
        )
        payload = {"id": cur.lastrowid, "ts": ts, "kind": kind, "severity": severity,
                   "device_id": device_id, "message": message, "data": data or {}}
        self.publish("event", payload)
        return int(cur.lastrowid)
