"""AWS STS AssumeRoleWithWebIdentity Federation Engine."""

from datetime import datetime, timedelta, timezone
import hashlib
import os
import secrets
from typing import Any, Dict, List, Optional
from .models import AWSCredentials, JWTSVID
from .oidc_issuer import OIDCIssuer


class STSFederationError(Exception):
    """Raised when STS AssumeRoleWithWebIdentity fails trust or token checks."""
    pass


class IAMRoleTrustPolicy:
    """Represents an AWS IAM Role Trust Policy for OIDC Federation."""

    def __init__(
        self,
        role_arn: str,
        issuer_url: str,
        allowed_audiences: List[str],
        allowed_subjects: List[str],
        max_session_duration_seconds: int = 3600,
    ):
        self.role_arn = role_arn
        self.issuer_url = issuer_url.rstrip("/")
        self.allowed_audiences = allowed_audiences
        self.allowed_subjects = allowed_subjects
        self.max_session_duration_seconds = max_session_duration_seconds

    def evaluate(self, claims: Dict[str, Any]) -> bool:
        """Evaluate token claims against IAM trust policy conditions."""
        # Validate audience condition
        token_aud = claims.get("aud")
        if isinstance(token_aud, str):
            token_aud = [token_aud]
        if not any(aud in self.allowed_audiences for aud in (token_aud or [])):
            return False

        # Validate subject condition (SPIFFE ID)
        token_sub = claims.get("sub") or claims.get("spiffe_id")
        if not token_sub:
            return False

        # Match exact or wildcard subject
        for allowed in self.allowed_subjects:
            if allowed == "*" or allowed == token_sub:
                return True
            if allowed.endswith("*") and token_sub.startswith(allowed[:-1]):
                return True

        return False


class AWSSTSFederator:
    """Simulates/Executes AWS STS AssumeRoleWithWebIdentity with cryptographic validation."""

    def __init__(self, oidc_issuer: OIDCIssuer):
        self.oidc_issuer = oidc_issuer
        self.roles: Dict[str, IAMRoleTrustPolicy] = {}

    def register_role(self, trust_policy: IAMRoleTrustPolicy) -> None:
        self.roles[trust_policy.role_arn] = trust_policy

    def assume_role_with_web_identity(
        self,
        role_arn: str,
        role_session_name: str,
        web_identity_token: str,
        duration_seconds: int = 900,
    ) -> AWSCredentials:
        """Exchange verified OIDC JWT-SVID for temporary AWS STS credentials."""
        if role_arn not in self.roles:
            raise STSFederationError(f"Role not found: {role_arn}")

        policy = self.roles[role_arn]

        # 1. Cryptographically verify the Web Identity Token
        try:
            claims = self.oidc_issuer.verify_token(web_identity_token)
        except Exception as e:
            raise STSFederationError(f"Token signature verification failed: {str(e)}") from e

        # 2. Verify Issuer match
        token_iss = claims.get("iss", "").rstrip("/")
        if token_iss != policy.issuer_url:
            raise STSFederationError(
                f"InvalidIdentityToken: Token issuer '{token_iss}' does not match provider '{policy.issuer_url}'"
            )

        # 3. Evaluate IAM Role Trust Policy conditions
        if not policy.evaluate(claims):
            sub = claims.get("sub")
            raise STSFederationError(
                f"AccessDenied: Subject '{sub}' is not authorized to assume role '{role_arn}'"
            )

        # 4. Enforce session duration bounds (900s to max_session_duration)
        effective_duration = max(900, min(duration_seconds, policy.max_session_duration_seconds))
        now = datetime.now(timezone.utc)
        expiration = now + timedelta(seconds=effective_duration)

        # 5. Mint ephemeral AWS IAM credentials
        random_suffix = secrets.token_hex(8).upper()
        access_key_id = f"ASIA{random_suffix}"
        secret_access_key = secrets.token_urlsafe(32)
        session_token = f"IQoJb3JpZ2luX2VjEAMaCXVzLWVhc3QtMS{secrets.token_urlsafe(64)}"
        role_id_hash = hashlib.sha256(role_arn.encode()).hexdigest()[:16].upper()
        assumed_role_id = f"AROA{role_id_hash}:{role_session_name}"

        return AWSCredentials(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
            expiration=expiration,
            role_arn=role_arn,
            assumed_role_id=assumed_role_id,
        )
