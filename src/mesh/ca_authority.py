"""X.509 SPIFFE Certificate Authority and SVID Issuer."""

from datetime import datetime, timedelta, timezone
from typing import Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .models import SpiffeId, X509SVID


class SpiffeCertificateAuthority:
    """Manages Root CA and mints cryptographic X.509 SVIDs with SAN URIs."""

    def __init__(self, trust_domain: str = "prod.aws.internal", ca_ttl_days: int = 365):
        self.trust_domain = trust_domain
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.ca_cert = self._create_root_ca(ca_ttl_days)

    def _create_root_ca(self, ttl_days: int) -> x509.Certificate:
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZeroSecret Workload Identity Mesh"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"SPIFFE Root CA ({self.trust_domain})"),
        ])
        now = datetime.now(timezone.utc)
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=ttl_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.UniformResourceIdentifier(f"spiffe://{self.trust_domain}"),
                ]),
                critical=False,
            )
            .sign(self.ca_key, hashes.SHA256())
        )

    def issue_svid(self, spiffe_id: SpiffeId, ttl_minutes: int = 15) -> X509SVID:
        """Mint a short-lived X.509 SVID with SPIFFE ID in Subject Alternative Name (SAN)."""
        if spiffe_id.trust_domain != self.trust_domain:
            raise ValueError(
                f"Trust domain mismatch: expected {self.trust_domain}, got {spiffe_id.trust_domain}"
            )

        workload_key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZeroSecret Mesh Workload"),
            x509.NameAttribute(NameOID.COMMON_NAME, spiffe_id.service_account or "workload"),
        ])
        now = datetime.now(timezone.utc)
        not_after = now + timedelta(minutes=ttl_minutes)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(workload_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(seconds=30))
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                ]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.UniformResourceIdentifier(spiffe_id.to_uri()),
                ]),
                critical=True,
            )
            .sign(self.ca_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        key_pem = workload_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        return X509SVID(
            spiffe_id=spiffe_id,
            cert_pem=cert_pem,
            key_pem=key_pem,
            serial_number=cert.serial_number,
            not_before=now,
            not_after=not_after,
        )

    def get_ca_bundle_pem(self) -> str:
        return self.ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
