"""Gestión de la PKI del servidor y de los contextos TLS."""

from __future__ import annotations

import datetime as dt
import logging
import socket
import ssl
from pathlib import Path

import psutil
from cryptography import x509

from netcommand.common import crypto
from netcommand.common.crypto import SecretBox
from netcommand.common.secrets_store import load_or_create_secret

log = logging.getLogger(__name__)


def local_addresses() -> list[str]:
    names = ["localhost", "127.0.0.1", "::1"]
    try:
        host = socket.gethostname()
        names.append(host)
        fqdn = socket.getfqdn()
        if fqdn and fqdn != host:
            names.append(fqdn)
    except OSError:
        pass
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family == socket.AF_INET and not a.address.startswith("169.254."):
                names.append(a.address)
    return names


class ServerPKI:
    def __init__(self, pki_dir: Path, secrets_dir: Path, extra_names: list[str] | None = None,
                 machine_scope: bool = False):
        self.dir = pki_dir
        self.secrets_dir = secrets_dir
        self.extra_names = [n for n in (extra_names or []) if n]
        self.machine_scope = machine_scope
        self.master = SecretBox(load_or_create_secret(secrets_dir / "master.key", 32, machine_scope))
        self.ca_cert_path = pki_dir / "ca.crt"
        self.ca_key_path = pki_dir / "ca.key"
        self.server_cert_path = pki_dir / "server.crt"
        self.server_key_path = pki_dir / "server.key"
        self._ca_cert: x509.Certificate | None = None
        self._ca_key = None

    # Contraseñas de las claves privadas en disco, derivadas de la clave maestra protegida.
    @property
    def ca_key_password(self) -> bytes:
        return self.master.derive("pki/ca-key").hex().encode()

    @property
    def server_key_password(self) -> bytes:
        return self.master.derive("pki/server-key").hex().encode()

    def ensure(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        if not self.ca_cert_path.exists() or not self.ca_key_path.exists():
            log.info("Generando autoridad de certificación privada")
            key, cert = crypto.generate_ca()
            self.ca_key_path.write_bytes(crypto.key_to_pem(key, self.ca_key_password))
            self.ca_cert_path.write_bytes(crypto.cert_to_pem(cert))
        self._ca_cert = crypto.cert_from_pem(self.ca_cert_path.read_bytes())
        self._ca_key = crypto.key_from_pem(self.ca_key_path.read_bytes(), self.ca_key_password)
        if self._server_cert_needs_renewal():
            self.issue_server_certificate()

    def _wanted_names(self) -> list[str]:
        return local_addresses() + self.extra_names

    def _server_cert_needs_renewal(self) -> bool:
        if not self.server_cert_path.exists() or not self.server_key_path.exists():
            return True
        try:
            cert = crypto.cert_from_pem(self.server_cert_path.read_bytes())
            crypto.key_from_pem(self.server_key_path.read_bytes(), self.server_key_password)
        except Exception:
            return True
        remaining = cert.not_valid_after_utc - dt.datetime.now(dt.timezone.utc)
        if remaining < dt.timedelta(days=30):
            return True
        if not crypto.verify_issued_by(cert, self.ca_cert):
            return True
        try:
            sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            present = {str(v).lower() for v in sans.get_values_for_type(x509.DNSName)}
            present |= {str(v) for v in sans.get_values_for_type(x509.IPAddress)}
        except x509.ExtensionNotFound:
            present = set()
        missing = [n for n in self._wanted_names() if n.lower() not in present and n not in present]
        if missing:
            log.info("El certificado del servidor no incluye %s; se renovará", ", ".join(missing))
            return True
        return False

    def issue_server_certificate(self) -> None:
        names = self._wanted_names()
        key, cert = crypto.issue_server_cert(self.ca_key, self.ca_cert, names)
        self.server_key_path.write_bytes(crypto.key_to_pem(key, self.server_key_password))
        self.server_cert_path.write_bytes(crypto.cert_to_pem(cert))
        log.info("Certificado de servidor emitido para: %s", ", ".join(names))

    @property
    def ca_cert(self) -> x509.Certificate:
        if self._ca_cert is None:
            raise RuntimeError("PKI no inicializada")
        return self._ca_cert

    @property
    def ca_key(self):
        if self._ca_key is None:
            raise RuntimeError("PKI no inicializada")
        return self._ca_key

    @property
    def ca_fingerprint(self) -> str:
        return crypto.fingerprint(self.ca_cert)

    @property
    def ca_pem(self) -> str:
        return self.ca_cert_path.read_text()

    def server_cert(self) -> x509.Certificate:
        return crypto.cert_from_pem(self.server_cert_path.read_bytes())

    def sign_device(self, csr_pem: str, device_id: str, days: int) -> x509.Certificate:
        csr = crypto.load_csr(csr_pem, device_id)
        return crypto.sign_device_csr(self.ca_key, self.ca_cert, csr, device_id, days)

    def agent_ssl_context(self) -> ssl.SSLContext:
        """TLS del canal de agentes: certificado de cliente opcional en el apretón
        (necesario para el enrolamiento) y obligatorio para cualquier operación
        que no sea enrolamiento, comprobado por la aplicación."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(self.server_cert_path, self.server_key_path, password=self.server_key_password)
        ctx.load_verify_locations(cafile=str(self.ca_cert_path))
        ctx.verify_mode = ssl.CERT_OPTIONAL
        return ctx

    def console_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(self.server_cert_path, self.server_key_path, password=self.server_key_password)
        return ctx
