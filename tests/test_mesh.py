"""Unit and integration test suite for Zero-Secret Workload Identity Mesh."""

import pytest
import time
from datetime import datetime, timezone, timedelta

from src.mesh.models import SpiffeId, AttestationEvidence, X509SVID, JWTSVID, AWSCredentials
from src.mesh.ca_authority import SpiffeCertificateAuthority
from src.mesh.attestor import WorkloadAttestor, AttestationError
from src.mesh.oidc_issuer import OIDCIssuer
from src.mesh.sts_federator import AWSSTSFederator, IAMRoleTrustPolicy, STSFederationError
from src.mesh.secretless_broker import SecretlessTokenBroker


@pytest.fixture
def trust_domain():
    return "prod.aws.internal"


@pytest.fixture
def ca(trust_domain):
    return SpiffeCertificateAuthority(trust_domain=trust_domain)


@pytest.fixture
def attestor(trust_domain):
    return WorkloadAttestor(trust_domain=trust_domain)


@pytest.fixture
def oidc():
    return OIDCIssuer(issuer_url="https://oidc.identity.mesh.internal")


@pytest.fixture
def sts_federator(oidc):
    sts = AWSSTSFederator(oidc_issuer=oidc)
    policy = IAMRoleTrustPolicy(
        role_arn="arn:aws:iam::123456789012:role/PaymentServiceRole",
        issuer_url=oidc.issuer_url,
        allowed_audiences=["sts.amazonaws.com"],
        allowed_subjects=["spiffe://prod.aws.internal/ns/prod/sa/payment-service"],
    )
    sts.register_role(policy)
    return sts


@pytest.fixture
def valid_evidence():
    return AttestationEvidence(
        workload_name="payment-service",
        namespace="prod",
        service_account="payment-service",
        cgroup_path="/sys/fs/cgroup/kubepods/pod123/payment-service",
        pid=1234,
        binary_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        container_uid=10001,
    )


# ==========================================================
# 1. SPIFFE ID Parsing and Model Tests
# ==========================================================

def test_spiffe_id_parsing_valid():
    uri = "spiffe://prod.aws.internal/ns/prod/sa/payment-service"
    spiffe_id = SpiffeId.from_string(uri)
    assert spiffe_id.trust_domain == "prod.aws.internal"
    assert spiffe_id.path == "/ns/prod/sa/payment-service"
    assert spiffe_id.namespace == "prod"
    assert spiffe_id.service_account == "payment-service"
    assert spiffe_id.to_uri() == uri


def test_spiffe_id_parsing_invalid_scheme():
    with pytest.raises(ValueError, match="Invalid SPIFFE ID scheme"):
        SpiffeId.from_string("https://prod.aws.internal/ns/prod")


def test_spiffe_id_parsing_empty_domain():
    with pytest.raises(ValueError, match="Empty trust domain"):
        SpiffeId.from_string("spiffe:///ns/prod/sa/app")


def test_spiffe_id_from_k8s():
    sid = SpiffeId.from_k8s("corp.internal", "security", "vault-agent")
    assert sid.to_uri() == "spiffe://corp.internal/ns/security/sa/vault-agent"
    assert sid.namespace == "security"
    assert sid.service_account == "vault-agent"


# ==========================================================
# 2. Certificate Authority & X.509 SVID Tests
# ==========================================================

def test_ca_root_and_bundle(ca, trust_domain):
    bundle = ca.get_ca_bundle_pem()
    assert "-----BEGIN CERTIFICATE-----" in bundle
    assert "-----END CERTIFICATE-----" in bundle
    assert ca.ca_cert.issuer == ca.ca_cert.subject


def test_issue_x509_svid_san_uri(ca):
    sid = SpiffeId.from_k8s("prod.aws.internal", "prod", "payment-service")
    svid = ca.issue_svid(sid, ttl_minutes=15)
    assert svid.spiffe_id == sid
    assert "-----BEGIN CERTIFICATE-----" in svid.cert_pem
    assert "-----BEGIN PRIVATE KEY-----" in svid.key_pem
    assert not svid.is_expired
    assert svid.not_after > svid.not_before


def test_issue_x509_svid_trust_domain_mismatch(ca):
    foreign_sid = SpiffeId.from_k8s("external.attacker.io", "prod", "payment-service")
    with pytest.raises(ValueError, match="Trust domain mismatch"):
        ca.issue_svid(foreign_sid)


# ==========================================================
# 3. OIDC Issuer & JWT-SVID Tests
# ==========================================================

def test_oidc_discovery_and_jwks(oidc):
    config = oidc.get_openid_configuration()
    assert config["issuer"] == oidc.issuer_url
    assert "RS256" in config["id_token_signing_alg_values_supported"]

    jwks = oidc.get_jwks()
    assert "keys" in jwks
    assert len(jwks["keys"]) == 1
    key = jwks["keys"][0]
    assert key["kty"] == "RSA"
    assert key["kid"] == oidc.kid
    assert "n" in key and "e" in key


def test_oidc_jwt_svid_signing_and_verification(oidc):
    sid = SpiffeId.from_k8s("prod.aws.internal", "prod", "payment-service")
    jwt_svid = oidc.issue_jwt_svid(sid, audience="sts.amazonaws.com", ttl_minutes=10)

    assert not jwt_svid.is_expired
    assert jwt_svid.claims["sub"] == sid.to_uri()
    assert jwt_svid.claims["aud"] == "sts.amazonaws.com"

    verified_claims = oidc.verify_token(jwt_svid.token, expected_audience="sts.amazonaws.com")
    assert verified_claims["sub"] == sid.to_uri()


def test_oidc_jwt_svid_invalid_audience(oidc):
    sid = SpiffeId.from_k8s("prod.aws.internal", "prod", "payment-service")
    jwt_svid = oidc.issue_jwt_svid(sid, audience="sts.amazonaws.com")

    with pytest.raises(ValueError, match="Audience mismatch"):
        oidc.verify_token(jwt_svid.token, expected_audience="custom-api.internal")


# ==========================================================
# 4. Attestation Tests
# ==========================================================

def test_attestor_success(attestor, valid_evidence):
    spiffe_id = attestor.attest(valid_evidence)
    assert spiffe_id.to_uri() == "spiffe://prod.aws.internal/ns/prod/sa/payment-service"


def test_attestor_untrusted_namespace(attestor, valid_evidence):
    valid_evidence.namespace = "rogue-namespace"
    with pytest.raises(AttestationError, match="Untrusted namespace"):
        attestor.attest(valid_evidence)


def test_attestor_invalid_cgroup(attestor, valid_evidence):
    valid_evidence.cgroup_path = "/sys/fs/cgroup/user.slice/user-1000.service"
    with pytest.raises(AttestationError, match="Invalid cgroup hierarchy"):
        attestor.attest(valid_evidence)


def test_attestor_root_container_rejected(attestor, valid_evidence):
    valid_evidence.container_uid = 0
    with pytest.raises(AttestationError, match="Workload running as root"):
        attestor.attest(valid_evidence)


def test_attestor_tampered_binary(attestor, valid_evidence):
    valid_evidence.binary_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
    with pytest.raises(AttestationError, match="Integrity check failed"):
        attestor.attest(valid_evidence)


# ==========================================================
# 5. STS AssumeRoleWithWebIdentity Tests
# ==========================================================

def test_sts_assume_role_success(sts_federator, oidc):
    sid = SpiffeId.from_k8s("prod.aws.internal", "prod", "payment-service")
    jwt_svid = oidc.issue_jwt_svid(sid, audience="sts.amazonaws.com")

    creds = sts_federator.assume_role_with_web_identity(
        role_arn="arn:aws:iam::123456789012:role/PaymentServiceRole",
        role_session_name="payment-pod-session",
        web_identity_token=jwt_svid.token,
    )

    assert creds.access_key_id.startswith("ASIA")
    assert len(creds.secret_access_key) > 30
    assert not creds.is_expired
    assert creds.assumed_role_id.endswith(":payment-pod-session")


def test_sts_assume_role_unauthorized_subject(sts_federator, oidc):
    unauth_sid = SpiffeId.from_k8s("prod.aws.internal", "core", "unauthorized-worker")
    jwt_svid = oidc.issue_jwt_svid(unauth_sid, audience="sts.amazonaws.com")

    with pytest.raises(STSFederationError, match="AccessDenied: Subject"):
        sts_federator.assume_role_with_web_identity(
            role_arn="arn:aws:iam::123456789012:role/PaymentServiceRole",
            role_session_name="unauth-session",
            web_identity_token=jwt_svid.token,
        )


def test_sts_assume_role_unknown_role(sts_federator, oidc):
    sid = SpiffeId.from_k8s("prod.aws.internal", "prod", "payment-service")
    jwt_svid = oidc.issue_jwt_svid(sid)

    with pytest.raises(STSFederationError, match="Role not found"):
        sts_federator.assume_role_with_web_identity(
            role_arn="arn:aws:iam::123456789012:role/NonExistentRole",
            role_session_name="session",
            web_identity_token=jwt_svid.token,
        )


# ==========================================================
# 6. Secretless Broker & Rotation Tests
# ==========================================================

def test_secretless_broker_lifecycle(ca, attestor, oidc, sts_federator, valid_evidence):
    broker = SecretlessTokenBroker(
        attestor=attestor,
        ca_authority=ca,
        oidc_issuer=oidc,
        sts_federator=sts_federator,
        role_arn="arn:aws:iam::123456789012:role/PaymentServiceRole",
        rotation_threshold_seconds=600,
    )

    # Initial acquisition
    creds1 = broker.get_aws_credentials(valid_evidence)
    assert creds1.access_key_id.startswith("ASIA")
    assert broker.rotation_count == 1

    # Cached hit (no re-rotation)
    creds_cached = broker.get_aws_credentials(valid_evidence, force_refresh=False)
    assert creds_cached.access_key_id == creds1.access_key_id
    assert broker.rotation_count == 1

    # Force rotation
    creds2 = broker.get_aws_credentials(valid_evidence, force_refresh=True)
    assert creds2.access_key_id != creds1.access_key_id
    assert broker.rotation_count == 2
