"""Data models for SPIFFE/SPIRE workload identity federation mesh."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class SpiffeId:
    """SPIFFE ID representation according to SPIFFE Standard."""
    trust_domain: str
    path: str

    @classmethod
    def from_string(cls, uri: str) -> "SpiffeId":
        if not uri.startswith("spiffe://"):
            raise ValueError(f"Invalid SPIFFE ID scheme: {uri}. Must start with 'spiffe://'")
        stripped = uri[len("spiffe://"):]
        if "/" not in stripped:
            raise ValueError(f"Invalid SPIFFE ID format: {uri}. Missing path.")
        parts = stripped.split("/", 1)
        trust_domain = parts[0]
        path = "/" + parts[1].strip("/")
        if not trust_domain:
            raise ValueError("Empty trust domain in SPIFFE ID.")
        return cls(trust_domain=trust_domain, path=path)

    @classmethod
    def from_k8s(cls, trust_domain: str, namespace: str, service_account: str) -> "SpiffeId":
        return cls(trust_domain=trust_domain, path=f"/ns/{namespace}/sa/{service_account}")

    def to_uri(self) -> str:
        return f"spiffe://{self.trust_domain}{self.path}"

    @property
    def namespace(self) -> Optional[str]:
        match = re.search(r"/ns/([^/]+)", self.path)
        return match.group(1) if match else None

    @property
    def service_account(self) -> Optional[str]:
        match = re.search(r"/sa/([^/]+)", self.path)
        return match.group(1) if match else None

    def __str__(self) -> str:
        return self.to_uri()


@dataclass
class AttestationEvidence:
    """Kernel and container attestation evidence collected from node."""
    workload_name: str
    namespace: str
    service_account: str
    cgroup_path: str
    pid: int
    binary_sha256: str
    node_name: str = "k8s-worker-node-01"
    container_uid: int = 10001
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class X509SVID:
    """X.509 SPIFFE Verifiable Identity Document."""
    spiffe_id: SpiffeId
    cert_pem: str
    key_pem: Optional[str]
    serial_number: int
    not_before: datetime
    not_after: datetime

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.not_after


@dataclass
class JWTSVID:
    """JWT SPIFFE Verifiable Identity Document."""
    spiffe_id: SpiffeId
    token: str
    claims: Dict[str, Any]
    kid: str
    expires_at: datetime

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at


@dataclass
class AWSCredentials:
    """Ephemeral AWS credentials exchanged via STS AssumeRoleWithWebIdentity."""
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime
    role_arn: str
    assumed_role_id: str

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expiration
