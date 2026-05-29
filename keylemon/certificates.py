"""Short-lived certificate issuance for wrapper-managed mTLS."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from keylemon.models import AttestationResult
from keylemon.signing import canonical_json

ATTESTATION_DIGEST_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.1")


@dataclass(slots=True)
class CertificateAuthority:
    private_key: ec.EllipticCurvePrivateKey
    certificate: x509.Certificate

    @classmethod
    def create(cls, common_name: str = "keylemon broker ca") -> "CertificateAuthority":
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(UTC)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
            .sign(key, hashes.SHA256())
        )
        return cls(key, cert)

    def issue_leaf(
        self,
        *,
        subject_id: str,
        public_key,
        result: AttestationResult,
        lifetime: timedelta,
    ) -> x509.Certificate:
        now = datetime.now(UTC)
        digest = hashlib.sha256(canonical_json(result.to_dict())).digest()
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_id)]))
            .issuer_name(self.certificate.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(seconds=5))
            .not_valid_after(now + lifetime)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, True, True, False, False, False, False, False, False), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(x509.UnrecognizedExtension(ATTESTATION_DIGEST_OID, digest), critical=False)
            .sign(self.private_key, hashes.SHA256())
        )

    def certificate_pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)

    def private_key_pem(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


def attestation_digest_from_cert(cert: x509.Certificate) -> bytes | None:
    try:
        ext = cert.extensions.get_extension_for_oid(ATTESTATION_DIGEST_OID)
    except x509.ExtensionNotFound:
        return None
    if isinstance(ext.value, x509.UnrecognizedExtension):
        return ext.value.value
    return None


def attestation_result_digest(result: AttestationResult) -> bytes:
    return hashlib.sha256(canonical_json(result.to_dict())).digest()


def certificate_matches_attestation_result(cert: x509.Certificate, result: AttestationResult) -> bool:
    return attestation_digest_from_cert(cert) == attestation_result_digest(result)
