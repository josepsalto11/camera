"""Contraseñas, MFA (TOTP RFC 6238), sesiones y control de acceso por roles."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

# ---------------------------------------------------------------------------
# Roles y permisos
# ---------------------------------------------------------------------------

ROLES = ("admin", "operator", "viewer")
ROLE_TITLES = {"admin": "Administrador", "operator": "Operador", "viewer": "Solo lectura"}

_VIEWER = {"read"}
_OPERATOR = _VIEWER | {
    "scan.run", "device.edit", "space.edit", "action.query", "action.power", "action.media",
    "action.service", "files.read", "files.write", "alert.ack", "export", "audit.read", "rdp.launch",
}
_ADMIN = _OPERATOR | {
    "scan.ranges", "device.approve", "device.revoke", "pairing.create", "user.manage",
    "settings.edit", "alert.rules", "files.delete", "diagnostics",
}

PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": frozenset(_VIEWER),
    "operator": frozenset(_OPERATOR),
    "admin": frozenset(_ADMIN),
}


def has_permission(role: str, permission: str) -> bool:
    return permission in PERMISSIONS.get(role, frozenset())


# ---------------------------------------------------------------------------
# Contraseñas (scrypt de la biblioteca estándar)
# ---------------------------------------------------------------------------

_SCRYPT_N = 2 ** 15
_SCRYPT_R = 8
_SCRYPT_P = 1
_COMMON = {
    "password", "contraseña", "123456789012", "qwertyuiopas", "administrador", "netcommand",
    "passw0rd", "password1234", "adminadmin12", "letmein12345", "changeme1234",
}


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
                        maxmem=128 * 1024 * 1024, dklen=32)
    return "scrypt${}${}${}${}${}".format(
        _SCRYPT_N, _SCRYPT_R, _SCRYPT_P,
        base64.b64encode(salt).decode(), base64.b64encode(dk).decode(),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_b64, dk_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.scrypt(password.encode(), salt=salt, n=int(n), r=int(r), p=int(p),
                            maxmem=128 * 1024 * 1024, dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, expected)


# Hash ficticio para igualar tiempos cuando el usuario no existe.
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def password_problems(password: str, username: str = "") -> list[str]:
    problems = []
    if len(password) < 12:
        problems.append("debe tener al menos 12 caracteres")
    if len(password) > 256:
        problems.append("no puede superar 256 caracteres")
    classes = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ])
    if classes < 3:
        problems.append("debe combinar al menos 3 de: minúsculas, mayúsculas, números y símbolos")
    low = password.lower()
    if username and len(username) >= 3 and username.lower() in low:
        problems.append("no debe contener el nombre de usuario")
    if low in _COMMON:
        problems.append("es una contraseña demasiado común")
    return problems


# ---------------------------------------------------------------------------
# TOTP (RFC 6238) compatible con Microsoft Authenticator, Google Authenticator, etc.
# ---------------------------------------------------------------------------

TOTP_PERIOD = 30
TOTP_DIGITS = 6


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _b32decode(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    s += "=" * (-len(s) % 8)
    return base64.b32decode(s)


def totp_code(secret: str, step: int) -> str:
    key = _b32decode(secret)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** TOTP_DIGITS)
    return str(value).zfill(TOTP_DIGITS)


def verify_totp(secret: str, code: str, last_step: int | None, at: float | None = None,
                window: int = 1) -> int | None:
    """Devuelve el paso temporal aceptado o None. Rechaza la reutilización de códigos."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != TOTP_DIGITS:
        return None
    now_step = int((at if at is not None else time.time()) // TOTP_PERIOD)
    for delta in range(-window, window + 1):
        step = now_step + delta
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(totp_code(secret, step), code):
            return step
    return None


def provisioning_uri(secret: str, username: str, issuer: str = "NetCommand Pro") -> str:
    label = urllib.parse.quote(f"{issuer}:{username}")
    query = urllib.parse.urlencode({"secret": secret, "issuer": issuer, "digits": TOTP_DIGITS,
                                    "period": TOTP_PERIOD, "algorithm": "SHA1"})
    return f"otpauth://totp/{label}?{query}"


# ---------------------------------------------------------------------------
# Tokens de sesión y códigos de emparejamiento
# ---------------------------------------------------------------------------

def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


_PAIR_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # sin caracteres ambiguos


def new_pairing_code() -> str:
    raw = "".join(secrets.choice(_PAIR_ALPHABET) for _ in range(12))
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"


def normalize_pairing_code(code: str) -> str:
    c = "".join(ch for ch in code.upper() if ch.isalnum())
    return f"{c[:4]}-{c[4:8]}-{c[8:]}" if len(c) == 12 else c
