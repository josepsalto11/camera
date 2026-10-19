"""Configuración del servidor (archivo TOML sin secretos)."""

from __future__ import annotations

import dataclasses
import ipaddress
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PRIVATE_NETWORKS = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    "127.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10",
]


class ConfigError(Exception):
    pass


@dataclass
class ServerSection:
    data_dir: str = "data"
    # Consola (API REST + WebSocket para la interfaz). Por defecto sólo local.
    console_host: str = "127.0.0.1"
    console_port: int = 8770
    console_allowed_clients: list[str] = field(default_factory=lambda: ["127.0.0.1/32", "::1/128"])
    # Canal de agentes (WSS con autenticación mutua).
    agent_host: str = "0.0.0.0"
    agent_port: int = 8771
    allowed_agent_networks: list[str] = field(default_factory=lambda: list(PRIVATE_NETWORKS))
    # Nombre/IP que los agentes usarán para conectar (se incluye en el paquete de emparejamiento).
    public_address: str = ""
    extra_certificate_names: list[str] = field(default_factory=list)
    log_level: str = "INFO"


@dataclass
class SecuritySection:
    session_ttl_minutes: int = 480
    pairing_code_ttl_minutes: int = 15
    pairing_code_max_attempts: int = 5
    max_login_attempts: int = 5
    lockout_minutes: int = 15
    require_mfa_for_admin: bool = False
    dpapi_machine_scope: bool = False
    device_cert_days: int = 730


@dataclass
class MonitoringSection:
    heartbeat_interval_s: int = 15
    metrics_interval_s: int = 30
    offline_after_s: int = 60
    metrics_retention_days: int = 7
    events_retention_days: int = 90


@dataclass
class ScannerSection:
    max_hosts_per_scan: int = 1024
    max_concurrency: int = 64
    icmp_timeout_ms: int = 800
    tcp_timeout_ms: int = 700
    max_tcp_rate_per_s: int = 100
    max_ports_per_scan: int = 256
    default_ports: list[int] = field(default_factory=lambda: [22, 80, 135, 139, 443, 445, 3389, 5985, 5986, 8771])


@dataclass
class TasksSection:
    default_ttl_s: int = 600
    max_ttl_s: int = 86400
    max_concurrent_per_device: int = 4
    query_timeout_s: int = 30


@dataclass
class FilesSection:
    max_transfer_mb: int = 200
    chunk_kb: int = 256
    max_wallpaper_mb: int = 15


@dataclass
class ServerConfig:
    server: ServerSection = field(default_factory=ServerSection)
    security: SecuritySection = field(default_factory=SecuritySection)
    monitoring: MonitoringSection = field(default_factory=MonitoringSection)
    scanner: ScannerSection = field(default_factory=ScannerSection)
    tasks: TasksSection = field(default_factory=TasksSection)
    files: FilesSection = field(default_factory=FilesSection)
    base_dir: Path = field(default_factory=Path.cwd)

    @property
    def data_dir(self) -> Path:
        p = Path(self.server.data_dir)
        return p if p.is_absolute() else (self.base_dir / p).resolve()

    @property
    def db_path(self) -> Path:
        return self.data_dir / "netcommand.db"

    @property
    def pki_dir(self) -> Path:
        return self.data_dir / "pki"

    @property
    def secrets_dir(self) -> Path:
        return self.data_dir / "secrets"

    @property
    def logs_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def transfers_dir(self) -> Path:
        return self.data_dir / "transfers"

    @property
    def exports_dir(self) -> Path:
        return self.data_dir / "exports"

    def validate(self) -> None:
        s = self.server
        for net in s.console_allowed_clients + s.allowed_agent_networks:
            try:
                ipaddress.ip_network(net, strict=False)
            except ValueError:
                raise ConfigError(f"Red no válida en la configuración: {net}") from None
        for port in (s.console_port, s.agent_port):
            if not 1 <= port <= 65535:
                raise ConfigError(f"Puerto fuera de rango: {port}")
        if s.console_port == s.agent_port:
            raise ConfigError("La consola y el canal de agentes deben usar puertos distintos")
        if self.monitoring.heartbeat_interval_s < 5:
            raise ConfigError("heartbeat_interval_s debe ser al menos 5 segundos")
        if self.monitoring.metrics_interval_s < 5:
            raise ConfigError("metrics_interval_s debe ser al menos 5 segundos")
        if self.monitoring.offline_after_s < 2 * self.monitoring.heartbeat_interval_s:
            raise ConfigError("offline_after_s debe ser al menos el doble de heartbeat_interval_s")
        if not 1 <= self.scanner.max_concurrency <= 512:
            raise ConfigError("scanner.max_concurrency debe estar entre 1 y 512")
        if self.scanner.max_hosts_per_scan > 65536:
            raise ConfigError("scanner.max_hosts_per_scan no puede superar 65536")
        if not 16 <= self.files.chunk_kb <= 1024:
            raise ConfigError("files.chunk_kb debe estar entre 16 y 1024")


def _apply(section: Any, values: dict[str, Any], name: str) -> None:
    valid = {f.name: f for f in dataclasses.fields(section)}
    for key, value in values.items():
        if key not in valid:
            raise ConfigError(f"Opción desconocida [{name}] {key}")
        setattr(section, key, value)


def load_config(path: Path | None, base_dir: Path | None = None) -> ServerConfig:
    cfg = ServerConfig()
    if path is not None:
        cfg.base_dir = (base_dir or path.parent.parent).resolve()
        if path.exists():
            try:
                data = tomllib.loads(path.read_text(encoding="utf-8"))
            except tomllib.TOMLDecodeError as exc:
                raise ConfigError(f"Error de sintaxis en {path}: {exc}") from None
            for section_name, values in data.items():
                section = getattr(cfg, section_name, None)
                if section is None or not dataclasses.is_dataclass(section) or not isinstance(values, dict):
                    raise ConfigError(f"Sección desconocida [{section_name}] en {path}")
                _apply(section, values, section_name)
    elif base_dir is not None:
        cfg.base_dir = base_dir.resolve()
    cfg.validate()
    return cfg


def default_config_path(base_dir: Path) -> Path:
    return base_dir / "config" / "server.toml"
