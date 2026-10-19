"""Definición del protocolo entre servidor y agente.

Este módulo es la única fuente de verdad sobre qué acciones existen, qué
parámetros aceptan, qué permiso de consola requieren y qué categoría de la
política local del agente las habilita. Tanto el servidor como el agente
validan los parámetros con los mismos modelos, de modo que una petición
malformada se rechaza en ambos extremos.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from netcommand.common.version import PROTOCOL_VERSION

# Tamaño máximo de un mensaje WebSocket entre agente y servidor.
MAX_MESSAGE_BYTES = 2 * 1024 * 1024
# Tamaño de bloque por defecto para transferencias de archivos.
DEFAULT_CHUNK_BYTES = 256 * 1024
MAX_CHUNK_BYTES = 1024 * 1024

SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,256}$")
BLOB_ID_RE = re.compile(r"^[a-f0-9]{32}$")


class ParamsModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NoParams(ParamsModel):
    pass


class PowerParams(ParamsModel):
    delay_s: int = Field(default=60, ge=0, le=315_360_000)
    message: str = Field(default="", max_length=200)
    force: bool = False

    @field_validator("message")
    @classmethod
    def _clean_message(cls, v: str) -> str:
        # Se pasa a shutdown.exe como argumento: sin comillas ni saltos de línea.
        return re.sub(r'["\r\n\t]', " ", v).strip()


class DelayParams(ParamsModel):
    delay_s: int = Field(default=0, ge=0, le=3600)


class VolumeParams(ParamsModel):
    level: int = Field(ge=0, le=100)


class MuteParams(ParamsModel):
    muted: bool


class BrightnessParams(ParamsModel):
    level: int = Field(ge=0, le=100)


class WallpaperParams(ParamsModel):
    blob_id: str
    style: Literal["fill", "fit", "stretch", "center", "tile", "span"] = "fill"

    @field_validator("blob_id")
    @classmethod
    def _blob(cls, v: str) -> str:
        if not BLOB_ID_RE.match(v):
            raise ValueError("identificador de blob no válido")
        return v


class ProcessesParams(ParamsModel):
    limit: int = Field(default=200, ge=1, le=2000)
    sort: Literal["cpu", "memory", "name"] = "cpu"


class ServiceParams(ParamsModel):
    name: str

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not SERVICE_NAME_RE.match(v):
            raise ValueError("nombre de servicio no válido")
        return v


class PathParams(ParamsModel):
    path: str = Field(min_length=1, max_length=1024)


class StatParams(PathParams):
    hash: bool = False


class ReadChunkParams(PathParams):
    offset: int = Field(ge=0)
    length: int = Field(gt=0, le=MAX_CHUNK_BYTES)


class PlaceParams(ParamsModel):
    blob_id: str
    dest_path: str = Field(min_length=1, max_length=1024)
    overwrite: bool = False

    @field_validator("blob_id")
    @classmethod
    def _blob(cls, v: str) -> str:
        if not BLOB_ID_RE.match(v):
            raise ValueError("identificador de blob no válido")
        return v


class BlobPutParams(ParamsModel):
    blob_id: str
    offset: int = Field(ge=0)
    total_size: int = Field(ge=0)
    data_b64: str = Field(max_length=(MAX_CHUNK_BYTES * 4) // 3 + 8)

    @field_validator("blob_id")
    @classmethod
    def _blob(cls, v: str) -> str:
        if not BLOB_ID_RE.match(v):
            raise ValueError("identificador de blob no válido")
        return v


class BlobCommitParams(ParamsModel):
    blob_id: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @field_validator("blob_id")
    @classmethod
    def _blob(cls, v: str) -> str:
        if not BLOB_ID_RE.match(v):
            raise ValueError("identificador de blob no válido")
        return v


class BlobIdParams(ParamsModel):
    blob_id: str

    @field_validator("blob_id")
    @classmethod
    def _blob(cls, v: str) -> str:
        if not BLOB_ID_RE.match(v):
            raise ValueError("identificador de blob no válido")
        return v


@dataclass(frozen=True)
class ActionSpec:
    name: str
    title: str  # nombre visible en español
    params: type[ParamsModel]
    permission: str  # permiso de consola necesario
    policy: str  # clave de la política local del agente que debe estar habilitada
    disruptive: bool = False  # exige confirmación explícita
    internal: bool = False  # sólo lo usa el servidor (transferencias), no la API de tareas
    timeout_s: int = 30  # tiempo máximo de ejecución en el agente


_SPECS = [
    ActionSpec("power.shutdown", "Apagar", PowerParams, "action.power", "allow_power", disruptive=True),
    ActionSpec("power.restart", "Reiniciar", PowerParams, "action.power", "allow_power", disruptive=True),
    ActionSpec("power.cancel", "Cancelar apagado/reinicio", NoParams, "action.power", "allow_power"),
    ActionSpec("power.suspend", "Suspender", DelayParams, "action.power", "allow_power", disruptive=True, timeout_s=3700),
    ActionSpec("power.lock", "Bloquear sesión", DelayParams, "action.power", "allow_lock", disruptive=True, timeout_s=3700),
    ActionSpec("audio.get", "Consultar audio", NoParams, "action.query", "allow_audio"),
    ActionSpec("audio.set_volume", "Ajustar volumen", VolumeParams, "action.media", "allow_audio"),
    ActionSpec("audio.set_mute", "Silenciar/activar audio", MuteParams, "action.media", "allow_audio"),
    ActionSpec("display.get_brightness", "Consultar brillo", NoParams, "action.query", "allow_display"),
    ActionSpec("display.set_brightness", "Ajustar brillo", BrightnessParams, "action.media", "allow_display"),
    ActionSpec("display.set_wallpaper", "Cambiar fondo de pantalla", WallpaperParams, "action.media", "allow_wallpaper"),
    ActionSpec("system.info", "Inventario del sistema", NoParams, "action.query", "always"),
    ActionSpec("system.metrics", "Métricas actuales", NoParams, "action.query", "always"),
    ActionSpec("system.processes", "Procesos", ProcessesParams, "action.query", "allow_process_list"),
    ActionSpec("system.services", "Servicios", NoParams, "action.query", "allow_service_list"),
    ActionSpec("system.sessions", "Sesiones de usuario", NoParams, "action.query", "always"),
    ActionSpec("system.rdp_status", "Estado de Escritorio remoto", NoParams, "action.query", "always"),
    ActionSpec("service.restart", "Reiniciar servicio", ServiceParams, "action.service", "restartable_services",
               disruptive=True, timeout_s=90),
    ActionSpec("files.roots", "Carpetas aprobadas", NoParams, "files.read", "folders"),
    ActionSpec("files.list", "Listar carpeta", PathParams, "files.read", "folders"),
    ActionSpec("files.stat", "Información de archivo", StatParams, "files.read", "folders", timeout_s=300),
    ActionSpec("files.read_chunk", "Leer bloque", ReadChunkParams, "files.read", "folders", internal=True),
    ActionSpec("files.mkdir", "Crear carpeta", PathParams, "files.write", "folders"),
    ActionSpec("files.delete", "Eliminar", PathParams, "files.delete", "folders", disruptive=True),
    ActionSpec("files.place", "Colocar archivo", PlaceParams, "files.write", "folders", internal=True, timeout_s=300),
    ActionSpec("blob.put", "Recibir bloque", BlobPutParams, "files.write", "always", internal=True),
    ActionSpec("blob.commit", "Verificar transferencia", BlobCommitParams, "files.write", "always", internal=True,
               timeout_s=300),
    ActionSpec("blob.discard", "Descartar transferencia", BlobIdParams, "files.write", "always", internal=True),
]

ACTIONS: dict[str, ActionSpec] = {s.name: s for s in _SPECS}


class ProtocolError(ValueError):
    """Mensaje o parámetros inválidos."""


def get_action(name: str) -> ActionSpec:
    spec = ACTIONS.get(name)
    if spec is None:
        raise ProtocolError(f"Acción desconocida: {name}")
    return spec


def validate_params(action: str, params: dict[str, Any] | None) -> dict[str, Any]:
    """Valida y normaliza los parámetros de una acción. Lanza ProtocolError."""
    spec = get_action(action)
    try:
        model = spec.params.model_validate(params or {})
    except ValidationError as exc:
        errors = "; ".join(
            f"{'.'.join(str(p) for p in e['loc']) or 'parámetros'}: {e['msg']}" for e in exc.errors()
        )
        raise ProtocolError(f"Parámetros no válidos para {action}: {errors}") from None
    return model.model_dump()


# --------------------------------------------------------------------------
# Mensajes
# --------------------------------------------------------------------------

AGENT_TO_SERVER = {
    "hello", "heartbeat", "metrics", "inventory", "task_result", "task_ack", "pong", "goodbye",
}
SERVER_TO_AGENT = {"welcome", "task", "cancel", "ping", "config", "revoked", "error"}
ENROLL_TYPES = {"enroll.get_ca", "enroll.request", "enroll.status", "enroll.proof"}


def new_id() -> str:
    return uuid.uuid4().hex


def make_message(msg_type: str, **fields: Any) -> str:
    payload = {"type": msg_type, "v": PROTOCOL_VERSION, "ts": time.time()}
    payload.update(fields)
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def parse_message(raw: str | bytes, allowed: set[str]) -> dict[str, Any]:
    if isinstance(raw, bytes):
        if len(raw) > MAX_MESSAGE_BYTES:
            raise ProtocolError("Mensaje demasiado grande")
        raw = raw.decode("utf-8")
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ProtocolError("Mensaje demasiado grande")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProtocolError(f"JSON no válido: {exc}") from None
    if not isinstance(data, dict) or not isinstance(data.get("type"), str):
        raise ProtocolError("Mensaje sin tipo")
    if data["type"] not in allowed:
        raise ProtocolError(f"Tipo de mensaje no permitido: {data['type']}")
    return data


# Estados de inventario (valor interno -> etiqueta visible)
DEVICE_STATES = {
    "online": "En línea",
    "offline": "Desconectado",
    "not_enrolled": "No enrolado",
    "pending": "Pendiente de aprobación",
    "error": "Error",
    "revoked": "Revocado",
    "rejected": "Rechazado",
}
