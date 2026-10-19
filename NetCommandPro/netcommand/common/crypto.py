"""PKI privada de NetCommand: autoridad de certificación, certificado de
servidor y certificados de dispositivo (autenticación mutua TLS).

- La CA sólo firma dos tipos de certificado:
  * servidor: EKU serverAuth, CN fijo ``SERVER_CN``.
  * dispositivo: EKU clientAuth, CN = identificador del dispositivo.
- Los agentes comprueban explícitamente que el certificado del servidor
  tiene EKU serverAuth y CN ``SERVER_CN``, de modo que un dispositivo
  enrolado no puede hacerse pasar por el servidor ante otros agentes.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import ipaddress
import os
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SERVER_CN = "NetCommand Pro Server"
CA_CN = "NetCommand Pro Private CA"
ORG = "NetCommand Pro"


class CryptoError(Exception):
    pass


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def generate_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def key_to_pem(key: ec.EllipticCurvePrivateKey, password: bytes | None) -> bytes:
    enc = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)


def key_from_pem(data: bytes, password: bytes | None) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(data, password=password)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise CryptoError("Tipo de clave no soportado")
    return key


def cert_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def cert_from_pem(data: bytes | str) -> x509.Certificate:
    if isinstance(data, str):
        data = data.encode()
    return x509.load_pem_x509_certificate(data)


def cert_from_der(data: bytes) -> x509.Certificate:
    return x509.load_der_x509_certificate(data)


def fingerprint(cert: x509.Certificate) -> str:
    """Huella SHA-256 en hexadecimal minúscula (sin separadores)."""
    return cert.fingerprint(hashes.SHA256()).hex()


def fingerprint_der(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def pretty_fingerprint(fp: str) -> str:
    fp = fp.lower().replace(":", "")
    return ":".join(fp[i:i + 2] for i in range(0, len(fp), 2)).upper()


def generate_ca(validity_days: int = 3650) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = generate_private_key()
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, CA_CN),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
    ])
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _san_entries(names: list[str]) -> list[x509.GeneralName]:
    entries: list[x509.GeneralName] = []
    seen: set[str] = set()
    for n in names:
        n = n.strip()
        if not n or n.lower() in seen:
            continue
        seen.add(n.lower())
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            entries.append(x509.DNSName(n))
    return entries


def issue_server_cert(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    names: list[str],
    validity_days: int = 825,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = generate_private_key()
    now = _now()
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, SERVER_CN),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=False, content_commitment=False,
                data_encipherment=False, key_agreement=True, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
    )
    sans = _san_entries(names)
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return key, builder.sign(ca_key, hashes.SHA256())


def build_csr(key: ec.EllipticCurvePrivateKey, device_id: str) -> bytes:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_id)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def load_csr(pem: bytes | str, expected_cn: str) -> x509.CertificateSigningRequest:
    if isinstance(pem, str):
        pem = pem.encode()
    try:
        csr = x509.load_pem_x509_csr(pem)
    except ValueError as exc:
        raise CryptoError(f"CSR no válida: {exc}") from None
    if not csr.is_signature_valid:
        raise CryptoError("La firma de la CSR no es válida")
    if not isinstance(csr.public_key(), ec.EllipticCurvePublicKey):
        raise CryptoError("La CSR debe usar una clave EC")
    cns = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cns or cns[0].value != expected_cn:
        raise CryptoError("El CN de la CSR no coincide con el identificador del dispositivo")
    return csr


def sign_device_csr(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    csr: x509.CertificateSigningRequest,
    device_id: str,
    validity_days: int = 730,
) -> x509.Certificate:
    """Firma un certificado de cliente. Ignora cualquier extensión pedida en la CSR."""
    now = _now()
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, device_id),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=False, content_commitment=False,
                data_encipherment=False, key_agreement=True, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )


def has_eku(cert: x509.Certificate, oid: x509.ObjectIdentifier) -> bool:
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return False
    return oid in eku


def common_name(cert: x509.Certificate) -> str:
    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(cns[0].value) if cns else ""


def verify_issued_by(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(ca_cert)
    except (ValueError, TypeError, InvalidSignature):
        return False
    now = _now()
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def verify_server_cert(leaf_der: bytes, ca_cert: x509.Certificate) -> x509.Certificate:
    """Comprobación adicional que realiza el agente tras el apretón TLS."""
    leaf = cert_from_der(leaf_der)
    if not verify_issued_by(leaf, ca_cert):
        raise CryptoError("El certificado del servidor no está firmado por la CA emparejada o ha caducado")
    if not has_eku(leaf, ExtendedKeyUsageOID.SERVER_AUTH) or common_name(leaf) != SERVER_CN:
        raise CryptoError("El certificado presentado no es un certificado de servidor NetCommand")
    return leaf


def verify_client_cert(leaf_der: bytes, ca_cert: x509.Certificate) -> x509.Certificate:
    leaf = cert_from_der(leaf_der)
    if not verify_issued_by(leaf, ca_cert):
        raise CryptoError("Certificado de cliente no emitido por la CA o caducado")
    if not has_eku(leaf, ExtendedKeyUsageOID.CLIENT_AUTH):
        raise CryptoError("El certificado no es de cliente")
    return leaf


# --- Prueba de posesión de la clave privada (sondeo del enrolamiento) ------

def sign_challenge(key: ec.EllipticCurvePrivateKey, challenge: bytes) -> str:
    sig = key.sign(challenge, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode()


def verify_challenge(public_key: ec.EllipticCurvePublicKey, challenge: bytes, signature_b64: str) -> bool:
    try:
        public_key.verify(base64.b64decode(signature_b64), challenge, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


# --- Cifrado simétrico para secretos en base de datos ---------------------

@dataclass
class SecretBox:
    """AES-256-GCM con nonce aleatorio. Formato: b'NB1' + nonce(12) + ct."""

    key: bytes

    def __post_init__(self) -> None:
        if len(self.key) != 32:
            raise CryptoError("La clave maestra debe tener 32 bytes")

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        nonce = os.urandom(12)
        return b"NB1" + nonce + AESGCM(self.key).encrypt(nonce, plaintext, aad or None)

    def decrypt(self, blob: bytes, aad: bytes = b"") -> bytes:
        if not blob.startswith(b"NB1") or len(blob) < 3 + 12 + 16:
            raise CryptoError("Secreto cifrado con formato desconocido")
        nonce, ct = blob[3:15], blob[15:]
        try:
            return AESGCM(self.key).decrypt(nonce, ct, aad or None)
        except Exception:  # InvalidTag
            raise CryptoError("No se pudo descifrar el secreto (clave incorrecta o datos alterados)") from None

    def derive(self, label: str) -> bytes:
        """Deriva una subclave/contraseña estable para un propósito concreto."""
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=label.encode()).derive(self.key)
