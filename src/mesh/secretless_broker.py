"""Secretless In-Memory Token Broker and Automated Rotation Engine."""

from datetime import datetime, timezone, timedelta
from typing import Optional
from .models import AttestationEvidence, AWSCredentials, JWTSVID, X509SVID
from .attestor import WorkloadAttestor
from .ca_authority import SpiffeCertificateAuthority
from .oidc_issuer import OIDCIssuer
from .sts_federator import AWSSTSFederator


class SecretlessTokenBroker:
    """Zero-Secret in-memory token broker managing lifecycle, rotation, and federation."""

    def __init__(
        self,
        attestor: WorkloadAttestor,
        ca_authority: SpiffeCertificateAuthority,
        oidc_issuer: OIDCIssuer,
        sts_federator: AWSSTSFederator,
        role_arn: str,
        rotation_threshold_seconds: int = 180,
    ):
        self.attestor = attestor
        self.ca_authority = ca_authority
        self.oidc_issuer = oidc_issuer
        self.sts_federator = sts_federator
        self.role_arn = role_arn
        self.rotation_threshold_seconds = rotation_threshold_seconds

        # In-memory transient state
        self._current_x509: Optional[X509SVID] = None
        self._current_jwt: Optional[JWTSVID] = None
        self._current_aws_creds: Optional[AWSCredentials] = None
        self._rotation_count: int = 0

    @property
    def rotation_count(self) -> int:
        return self._rotation_count

    def get_aws_credentials(self, evidence: AttestationEvidence, force_refresh: bool = False) -> AWSCredentials:
        """Obtain valid AWS credentials, automatically rotating if near expiry."""
        now = datetime.now(timezone.utc)

        needs_rotation = (
            force_refresh
            or self._current_aws_creds is None
            or (self._current_aws_creds.expiration - now).total_seconds() < self.rotation_threshold_seconds
        )

        if needs_rotation:
            self._rotate(evidence)

        assert self._current_aws_creds is not None
        return self._current_aws_creds

    def get_x509_svid(self, evidence: AttestationEvidence) -> X509SVID:
        if self._current_x509 is None or self._current_x509.is_expired:
            spiffe_id = self.attestor.attest(evidence)
            self._current_x509 = self.ca_authority.issue_svid(spiffe_id)
        return self._current_x509

    def get_jwt_svid(self, evidence: AttestationEvidence) -> JWTSVID:
        if self._current_jwt is None or self._current_jwt.is_expired:
            spiffe_id = self.attestor.attest(evidence)
            self._current_jwt = self.oidc_issuer.issue_jwt_svid(spiffe_id)
        return self._current_jwt

    def _rotate(self, evidence: AttestationEvidence) -> None:
        """Execute full zero-secret attestation, SVID issuance, and STS federation."""
        # 1. Attest workload
        spiffe_id = self.attestor.attest(evidence)

        # 2. Issue fresh SVIDs
        self._current_x509 = self.ca_authority.issue_svid(spiffe_id, ttl_minutes=15)
        self._current_jwt = self.oidc_issuer.issue_jwt_svid(spiffe_id, ttl_minutes=15)

        # 3. Federate with AWS STS
        self._current_aws_creds = self.sts_federator.assume_role_with_web_identity(
            role_arn=self.role_arn,
            role_session_name=f"mesh-{spiffe_id.service_account or 'session'}",
            web_identity_token=self._current_jwt.token,
            duration_seconds=900,
        )
        self._rotation_count += 1
