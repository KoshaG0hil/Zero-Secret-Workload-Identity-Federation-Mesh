"""OpenID Connect (OIDC) Issuer and JWT-SVID Minting."""

import base64
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from .models import JWTSVID, SpiffeId


def int_to_base64url(val: int) -> str:
    """Encode an integer into base64url format for JWK."""
    byte_length = (val.bit_length() + 7) // 8
    val_bytes = val.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(val_bytes).decode("utf-8").rstrip("=")


def bytes_to_base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def base64url_to_bytes(s: str) -> bytes:
    rem = len(s) % 4
    if rem > 0:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s.encode("utf-8"))


class OIDCIssuer:
    """OIDC Provider issuing cryptographically signed JWT-SVIDs compatible with AWS STS."""

    def __init__(self, issuer_url: str = "https://oidc.identity.mesh.internal", kid: str = "mesh-key-2026-v1"):
        self.issuer_url = issuer_url
        self.kid = kid
        # RSA 2048 is mandatory for AWS STS OIDC federation
        self.private_key: RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key: RSAPublicKey = self.private_key.public_key()

    def get_openid_configuration(self) -> Dict[str, Any]:
        """Returns standard OpenID Connect Discovery metadata."""
        return {
            "issuer": self.issuer_url,
            "jwks_uri": f"{self.issuer_url}/.well-known/jwks.json",
            "response_types_supported": ["id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "claims_supported": ["sub", "iss", "aud", "exp", "iat", "spiffe_id"],
        }

    def get_jwks(self) -> Dict[str, List[Dict[str, Any]]]:
        """Returns JSON Web Key Set containing public RSA key components."""
        pub_numbers = self.public_key.public_numbers()
        jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": int_to_base64url(pub_numbers.n),
            "e": int_to_base64url(pub_numbers.e),
        }
        return {"keys": [jwk]}

    def issue_jwt_svid(
        self,
        spiffe_id: SpiffeId,
        audience: str = "sts.amazonaws.com",
        ttl_minutes: int = 15,
    ) -> JWTSVID:
        """Mint a signed RS256 JWT-SVID for the given SPIFFE ID."""
        now = int(time.time())
        exp = now + (ttl_minutes * 60)

        header = {
            "alg": "RS256",
            "typ": "JWT",
            "kid": self.kid,
        }

        claims = {
            "iss": self.issuer_url,
            "sub": spiffe_id.to_uri(),
            "aud": audience,
            "iat": now,
            "exp": exp,
            "spiffe_id": spiffe_id.to_uri(),
            "namespace": spiffe_id.namespace,
            "service_account": spiffe_id.service_account,
        }

        header_b64 = bytes_to_base64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        claims_b64 = bytes_to_base64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header_b64}.{claims_b64}".encode("ascii")

        signature = self.private_key.sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        sig_b64 = bytes_to_base64url(signature)

        token = f"{header_b64}.{claims_b64}.{sig_b64}"
        expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)

        return JWTSVID(
            spiffe_id=spiffe_id,
            token=token,
            claims=claims,
            kid=self.kid,
            expires_at=expires_at,
        )

    def verify_token(self, token: str, expected_audience: Optional[str] = None) -> Dict[str, Any]:
        """Verify JWT signature, issuer, and expiration."""
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Malformed JWT: expected 3 dot-separated parts")

        header_b64, claims_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{claims_b64}".encode("ascii")
        signature = base64url_to_bytes(sig_b64)

        # Cryptographic signature verification
        self.public_key.verify(
            signature,
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

        claims = json.loads(base64url_to_bytes(claims_b64).decode("utf-8"))

        now = int(time.time())
        if claims.get("exp", 0) < now:
            raise ValueError("Token is expired")

        if claims.get("iss") != self.issuer_url:
            raise ValueError(f"Issuer mismatch: expected {self.issuer_url}, got {claims.get('iss')}")

        if expected_audience and claims.get("aud") != expected_audience:
            raise ValueError(f"Audience mismatch: expected {expected_audience}, got {claims.get('aud')}")

        return claims
