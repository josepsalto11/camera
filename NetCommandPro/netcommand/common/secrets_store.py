"""Almacenamiento protegido de secretos locales.

En Windows se usa DPAPI (CryptProtectData), ligado a la cuenta de usuario
o, opcionalmente, al equipo. Nunca se guardan secretos en texto plano en
Windows. En otros sistemas (sólo desarrollo, pruebas y simulación) el
secreto se guarda con permisos 0600 y se marca como no protegido; las
herramientas de diagnóstico lo advierten.
"""

from __future__ import annotations

import ctypes
import logging
import os
import secrets
import sys
from pathlib import Path

log = logging.getLogger(__name__)

_DPAPI_MAGIC = b"NCP-DPAPI1\n"
_PLAIN_MAGIC = b"NCP-PLAIN1\n"
_ENTROPY = b"NetCommandPro/secrets/v1"

CRYPTPROTECT_UI_FORBIDDEN = 0x01
CRYPTPROTECT_LOCAL_MACHINE = 0x04


class SecretStoreError(Exception):
    pass


def dpapi_available() -> bool:
    return sys.platform == "win32"


if sys.platform == "win32":  # pragma: no cover - sólo Windows
    from ctypes import wintypes

    class _DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DataBlob), wintypes.LPCWSTR, ctypes.POINTER(_DataBlob),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DataBlob),
    ]
    _crypt32.CryptProtectData.restype = wintypes.BOOL
    _crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DataBlob), ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(_DataBlob),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DataBlob),
    ]
    _crypt32.CryptUnprotectData.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]

    def _blob(data: bytes) -> tuple[_DataBlob, ctypes.Array]:
        buf = ctypes.create_string_buffer(data, len(data))
        return _DataBlob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    def _dpapi_protect(data: bytes, machine_scope: bool) -> bytes:
        inp, _b1 = _blob(data)
        ent, _b2 = _blob(_ENTROPY)
        out = _DataBlob()
        flags = CRYPTPROTECT_UI_FORBIDDEN | (CRYPTPROTECT_LOCAL_MACHINE if machine_scope else 0)
        if not _crypt32.CryptProtectData(ctypes.byref(inp), "NetCommandPro", ctypes.byref(ent),
                                         None, None, flags, ctypes.byref(out)):
            raise SecretStoreError(f"CryptProtectData falló (error {ctypes.get_last_error()})")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            _kernel32.LocalFree(out.pbData)

    def _dpapi_unprotect(data: bytes) -> bytes:
        inp, _b1 = _blob(data)
        ent, _b2 = _blob(_ENTROPY)
        out = _DataBlob()
        if not _crypt32.CryptUnprotectData(ctypes.byref(inp), None, ctypes.byref(ent),
                                           None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
            raise SecretStoreError(
                "No se pudo descifrar el secreto con DPAPI. ¿Se ejecuta con la misma cuenta "
                f"que lo creó? (error {ctypes.get_last_error()})"
            )
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            _kernel32.LocalFree(out.pbData)


def protect(data: bytes, machine_scope: bool = False) -> bytes:
    if dpapi_available():
        return _DPAPI_MAGIC + _dpapi_protect(data, machine_scope)
    return _PLAIN_MAGIC + data


def unprotect(blob: bytes) -> bytes:
    if blob.startswith(_DPAPI_MAGIC):
        if not dpapi_available():
            raise SecretStoreError("Este secreto fue protegido con DPAPI y sólo puede abrirse en Windows")
        return _dpapi_unprotect(blob[len(_DPAPI_MAGIC):])
    if blob.startswith(_PLAIN_MAGIC):
        if dpapi_available():
            log.warning("Secreto sin protección DPAPI detectado; se recomienda regenerarlo")
        return blob[len(_PLAIN_MAGIC):]
    raise SecretStoreError("Formato de secreto desconocido")


def is_protected_file(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(len(_DPAPI_MAGIC)) == _DPAPI_MAGIC
    except OSError:
        return False


def write_secret_file(path: Path, data: bytes, machine_scope: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    blob = protect(data, machine_scope)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(blob)
    os.replace(tmp, path)
    if os.name != "nt":
        os.chmod(path, 0o600)


def read_secret_file(path: Path) -> bytes:
    try:
        blob = path.read_bytes()
    except FileNotFoundError:
        raise SecretStoreError(f"No existe el secreto {path}") from None
    return unprotect(blob)


def load_or_create_secret(path: Path, size: int = 32, machine_scope: bool = False) -> bytes:
    if path.exists():
        return read_secret_file(path)
    value = secrets.token_bytes(size)
    write_secret_file(path, value, machine_scope)
    log.info("Secreto creado en %s", path)
    return value
