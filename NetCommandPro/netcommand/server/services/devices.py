"""Dispositivos enrolados, estado calculado e inventario unificado."""

from __future__ import annotations

from typing import Any

from netcommand.common.protocol import DEVICE_STATES
from netcommand.common.util import dumps, loads, now
from netcommand.server.db import Database

JSON_FIELDS = {"macs": [], "ips": [], "tags": [], "capabilities": {}, "policy": {}, "inventory": {}}
EDITABLE_FIELDS = {"display_name", "location", "device_type", "tags"}


def device_state(row: dict[str, Any]) -> str:
    status = row.get("status")
    if status == "pending":
        return "pending"
    if status in ("revoked", "rejected"):
        return str(status)
    if row.get("last_error"):
        return "error"
    return "online" if row.get("online") else "offline"


def public_device(row: dict[str, Any], include_heavy: bool = False) -> dict[str, Any]:
    d = dict(row)
    for f, default in JSON_FIELDS.items():
        d[f] = loads(d.get(f), default)
    d.pop("csr_pem", None)
    if not include_heavy:
        d.pop("cert_pem", None)
        d.pop("inventory", None)
    d["state"] = device_state(row)
    d["state_label"] = DEVICE_STATES[d["state"]]
    d["name"] = d.get("display_name") or d.get("hostname") or d["id"][:8]
    d["online"] = bool(d.get("online"))
    d["simulated"] = bool(d.get("simulated"))
    d["kind"] = "device"
    return d


class DeviceService:
    def __init__(self, db: Database):
        self.db = db

    def get_row(self, device_id: str) -> dict[str, Any] | None:
        return self.db.one("SELECT * FROM devices WHERE id = ?", (device_id,))

    def get(self, device_id: str, heavy: bool = True) -> dict[str, Any] | None:
        row = self.get_row(device_id)
        return public_device(row, include_heavy=heavy) if row else None

    def all_rows(self) -> list[dict[str, Any]]:
        return self.db.query("SELECT * FROM devices ORDER BY COALESCE(NULLIF(display_name, ''), hostname)")

    def list(self, **filters: Any) -> list[dict[str, Any]]:
        devices = [public_device(r) for r in self.all_rows()]
        return [d for d in devices if matches_filters(d, filters)]

    def update(self, device_id: str, changes: dict[str, Any]) -> dict[str, Any]:
        unknown = set(changes) - EDITABLE_FIELDS
        if unknown:
            raise ValueError(f"Campos no editables: {', '.join(sorted(unknown))}")
        sets, params = [], []
        for key, value in changes.items():
            if key == "tags":
                if not isinstance(value, list) or not all(isinstance(t, str) for t in value):
                    raise ValueError("Las etiquetas deben ser una lista de textos")
                value = dumps(sorted({t.strip()[:40] for t in value if t.strip()}))
            elif not isinstance(value, str) or len(value) > 120:
                raise ValueError(f"Valor no válido para {key}")
            sets.append(f"{key} = ?")
            params.append(value)
        if sets:
            params.append(device_id)
            self.db.execute(f"UPDATE devices SET {', '.join(sets)} WHERE id = ?", params)
        d = self.get(device_id, heavy=False)
        if d is None:
            raise KeyError(device_id)
        return d

    def set_online(self, device_id: str, ip: str | None) -> None:
        self.db.execute("UPDATE devices SET online = 1, last_seen = ?, last_ip = COALESCE(?, last_ip) WHERE id = ?",
                        (now(), ip, device_id))

    def set_offline(self, device_id: str) -> None:
        self.db.execute("UPDATE devices SET online = 0 WHERE id = ?", (device_id,))

    def touch(self, device_id: str, errors: list[str] | None = None) -> None:
        err = "; ".join(errors)[:500] if errors else None
        self.db.execute(
            "UPDATE devices SET last_seen = ?, last_error = ?, last_error_at = CASE WHEN ? IS NULL THEN last_error_at"
            " ELSE ? END WHERE id = ?",
            (now(), err, err, now(), device_id),
        )

    def set_latency(self, device_id: str, ms: float) -> None:
        self.db.execute("UPDATE devices SET latency_ms = ? WHERE id = ?", (round(ms, 2), device_id))

    def update_from_hello(self, device_id: str, hello: dict[str, Any], ip: str) -> None:
        info = hello.get("info") or {}
        self.db.execute(
            "UPDATE devices SET hostname = ?, os_name = ?, os_version = ?, agent_version = ?, platform = ?,"
            " macs = ?, ips = ?, capabilities = ?, policy = ?, simulated = ?, last_ip = ? WHERE id = ?",
            (
                str(info.get("hostname", ""))[:255], str(info.get("os_name", ""))[:120],
                str(info.get("os_version", ""))[:120], str(hello.get("agent_version", ""))[:40],
                str(info.get("platform", ""))[:40],
                dumps([m for m in info.get("macs", []) if isinstance(m, str)][:32]),
                dumps([i for i in info.get("ips", []) if isinstance(i, str)][:64]),
                dumps(hello.get("capabilities") or {}), dumps(hello.get("policy") or {}),
                1 if hello.get("simulated") else 0, ip, device_id,
            ),
        )

    def set_inventory(self, device_id: str, inventory: dict[str, Any]) -> None:
        self.db.execute("UPDATE devices SET inventory = ?, inventory_at = ? WHERE id = ?",
                        (dumps(inventory), now(), device_id))

    def delete(self, device_id: str) -> None:
        self.db.execute("DELETE FROM devices WHERE id = ?", (device_id,))

    # ------------------------------------------------------------------
    def inventory(self, **filters: Any) -> list[dict[str, Any]]:
        """Dispositivos enrolados + equipos descubiertos sin agente."""
        items = [public_device(r) for r in self.all_rows()]
        hosts = self.db.query("SELECT * FROM hosts WHERE device_id IS NULL ORDER BY ip")
        known_macs = {m for d in items for m in d.get("macs", [])}
        for h in hosts:
            if h.get("mac") and h["mac"] in known_macs:
                continue
            items.append(public_host(h))
        return [i for i in items if matches_filters(i, filters)]


def public_host(h: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"host:{h['id']}",
        "host_id": h["id"],
        "kind": "host",
        "name": h.get("hostname") or h.get("netbios") or h["ip"],
        "hostname": h.get("hostname") or "",
        "netbios": h.get("netbios") or "",
        "display_name": "",
        "last_ip": h["ip"],
        "ips": [h["ip"]],
        "macs": [h["mac"]] if h.get("mac") else [],
        "vendor": h.get("vendor") or "",
        "os_name": "",
        "os_version": "",
        "tags": [],
        "location": "",
        "device_type": "",
        "online": h.get("status") == "up",
        "last_seen": h.get("last_seen"),
        "latency_ms": h.get("latency_ms"),
        "open_ports": loads(h.get("open_ports"), []),
        "state": "not_enrolled",
        "state_label": DEVICE_STATES["not_enrolled"],
        "network_status": h.get("status"),
        "simulated": False,
    }


def matches_filters(item: dict[str, Any], filters: dict[str, Any]) -> bool:
    q = (filters.get("q") or "").strip().lower()
    if q:
        haystack = " ".join(str(x) for x in [
            item.get("name"), item.get("hostname"), item.get("display_name"), item.get("last_ip"),
            " ".join(item.get("ips", [])), " ".join(item.get("macs", [])), item.get("os_name"),
            item.get("os_version"), " ".join(item.get("tags", [])), item.get("location"),
            item.get("device_type"), item.get("state_label"), item.get("vendor", ""), item.get("netbios", ""),
        ]).lower()
        if not all(term in haystack for term in q.split()):
            return False
    state = filters.get("state")
    if state and item.get("state") != state:
        return False
    os_filter = (filters.get("os") or "").lower()
    if os_filter and os_filter not in f"{item.get('os_name', '')} {item.get('os_version', '')}".lower():
        return False
    tag = (filters.get("tag") or "").lower()
    if tag and tag not in [t.lower() for t in item.get("tags", [])]:
        return False
    location = (filters.get("location") or "").lower()
    if location and location != (item.get("location") or "").lower():
        return False
    dtype = (filters.get("device_type") or "").lower()
    if dtype and dtype != (item.get("device_type") or "").lower():
        return False
    return True
