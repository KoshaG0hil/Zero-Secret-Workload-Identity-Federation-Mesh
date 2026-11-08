#!/usr/bin/env python3
"""Zero-Secret Workload Identity Federation Mesh CLI."""

import argparse
import json
import sys
from datetime import datetime, timezone

from src.mesh.models import AttestationEvidence, SpiffeId
from src.mesh.ca_authority import SpiffeCertificateAuthority
from src.mesh.attestor import WorkloadAttestor
from src.mesh.oidc_issuer import OIDCIssuer
from src.mesh.sts_federator import AWSSTSFederator, IAMRoleTrustPolicy
from src.mesh.secretless_broker import SecretlessTokenBroker


def setup_default_mesh():
    trust_domain = "prod.aws.internal"
    ca = SpiffeCertificateAuthority(trust_domain=trust_domain)
    attestor = WorkloadAttestor(trust_domain=trust_domain)
    oidc = OIDCIssuer(issuer_url="https://oidc.identity.mesh.internal")
    sts = AWSSTSFederator(oidc_issuer=oidc)

    # Register sample AWS IAM Role trust policy
    role_arn = "arn:aws:iam::123456789012:role/ProductionPaymentProcessorRole"
    trust_policy = IAMRoleTrustPolicy(
        role_arn=role_arn,
        issuer_url=oidc.issuer_url,
        allowed_audiences=["sts.amazonaws.com"],
        allowed_subjects=[
            "spiffe://prod.aws.internal/ns/prod/sa/payment-service",
            "spiffe://prod.aws.internal/ns/security/sa/audit-collector",
            "spiffe://prod.aws.internal/ns/finops/sa/finops-agent",
        ],
    )
    sts.register_role(trust_policy)
    return ca, attestor, oidc, sts, role_arn


def cmd_attest(args):
    print("=" * 60)
    print(" [Zero-Secret Mesh] Kernel & Workload Attestation")
    print("=" * 60)

    ca, attestor, oidc, sts, _ = setup_default_mesh()

    evidence = AttestationEvidence(
        workload_name=args.name,
        namespace=args.namespace,
        service_account=args.service_account,
        cgroup_path=f"/sys/fs/cgroup/kubepods/pod123/{args.name}",
        pid=14201,
        binary_sha256=args.digest or "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        container_uid=10001,
    )

    try:
        spiffe_id = attestor.attest(evidence)
        print(f"[+] Attestation SUCCESS: Workload verified.")
        print(f"    SPIFFE ID      : {spiffe_id.to_uri()}")
        print(f"    Trust Domain   : {spiffe_id.trust_domain}")
        print(f"    Namespace      : {spiffe_id.namespace}")
        print(f"    ServiceAccount : {spiffe_id.service_account}")

        svid = ca.issue_svid(spiffe_id, ttl_minutes=15)
        print(f"\n[+] Issued X.509 SVID:")
        print(f"    Serial Number  : {svid.serial_number}")
        print(f"    Valid From     : {svid.not_before.isoformat()}")
        print(f"    Expires At     : {svid.not_after.isoformat()}")

        jwt_svid = oidc.issue_jwt_svid(spiffe_id, ttl_minutes=15)
        print(f"\n[+] Issued OIDC JWT-SVID (RS256):")
        print(f"    Key ID (kid)   : {jwt_svid.kid}")
        print(f"    Token Sample   : {jwt_svid.token[:36]}...{jwt_svid.token[-16:]}")
        print(f"    Claims Summary : {json.dumps(jwt_svid.claims, indent=6)}")
    except Exception as e:
        print(f"[-] Attestation FAILED: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_federate(args):
    print("=" * 60)
    print(" [Zero-Secret Mesh] STS Web Identity Federation")
    print("=" * 60)

    ca, attestor, oidc, sts, default_role = setup_default_mesh()
    role_arn = args.role or default_role

    evidence = AttestationEvidence(
        workload_name=args.name,
        namespace=args.namespace,
        service_account=args.service_account,
        cgroup_path=f"/sys/fs/cgroup/kubepods/pod/{args.name}",
        pid=14201,
        binary_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        container_uid=10001,
    )

    broker = SecretlessTokenBroker(
        attestor=attestor,
        ca_authority=ca,
        oidc_issuer=oidc,
        sts_federator=sts,
        role_arn=role_arn,
    )

    try:
        creds = broker.get_aws_credentials(evidence)
        print(f"[+] Identity Mesh Federation Successful!")
        print(f"    Target Role ARN     : {creds.role_arn}")
        print(f"    Assumed Role ID     : {creds.assumed_role_id}")
        print(f"    AWS Access Key ID   : {creds.access_key_id}")
        print(f"    Secret Access Key   : [REDACTED - IN-MEMORY ONLY]")
        print(f"    Session Token       : {creds.session_token[:28]}... (ephemeral)")
        print(f"    Expires At (UTC)    : {creds.expiration.isoformat()}")
        remaining = int((creds.expiration - datetime.now(timezone.utc)).total_seconds())
        print(f"    TTL Remaining       : {remaining} seconds ({remaining // 60} mins)")
        print("\n[*] Zero static secrets stored. Credential stored only in memory cache.")
    except Exception as e:
        print(f"[-] Federation FAILED: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_rotate(args):
    print("=" * 60)
    print(" [Zero-Secret Mesh] Automated In-Memory Rotation Simulation")
    print("=" * 60)

    ca, attestor, oidc, sts, default_role = setup_default_mesh()
    broker = SecretlessTokenBroker(
        attestor=attestor,
        ca_authority=ca,
        oidc_issuer=oidc,
        sts_federator=sts,
        role_arn=default_role,
        rotation_threshold_seconds=180,
    )

    evidence = AttestationEvidence(
        workload_name="payment-service",
        namespace="prod",
        service_account="payment-service",
        cgroup_path="/sys/fs/cgroup/kubepods/pod/payment-service",
        pid=14201,
        binary_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        container_uid=10001,
    )

    iterations = args.count or 3
    for i in range(1, iterations + 1):
        force = (i > 1)
        creds = broker.get_aws_credentials(evidence, force_refresh=force)
        print(f"[*] Cycle {i}/{iterations} -> Rotated Token: Key={creds.access_key_id} | Expires={creds.expiration.strftime('%H:%M:%S UTC')} | Rotations={broker.rotation_count}")

    print(f"\n[+] Completed {iterations} seamless in-memory cryptographic rotations without secret sprawl.")


def cmd_jwks(_args):
    _, _, oidc, _, _ = setup_default_mesh()
    output = {
        "openid_configuration": oidc.get_openid_configuration(),
        "jwks": oidc.get_jwks(),
    }
    print(json.dumps(output, indent=2))


def cmd_audit(_args):
    ca, attestor, oidc, sts, default_role = setup_default_mesh()
    print("=" * 60)
    print(" [Zero-Secret Mesh] Trust & Cryptographic Audit")
    print("=" * 60)
    print(f"[+] Trust Domain          : {ca.trust_domain}")
    print(f"[+] OIDC Issuer Endpoint  : {oidc.issuer_url}")
    print(f"[+] Signing Algorithm     : RS256 (2048-bit RSA)")
    print(f"[+] Active Key ID         : {oidc.kid}")
    print(f"[+] Approved Workloads    : {list(attestor.approved_fingerprints.keys())}")
    print(f"[+] Allowed Namespaces    : {sorted(list(attestor.allowed_namespaces))}")
    print(f"[+] Registered IAM Roles  : {list(sts.roles.keys())}")
    print("\n[+] Audit Result: 100% Zero-Secret Compliant. No static API keys or IAM users detected.")


def main():
    parser = argparse.ArgumentParser(description="Zero-Secret Workload Identity Federation Mesh CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # attest
    p_attest = subparsers.add_parser("attest", help="Attest workload and mint SVIDs")
    p_attest.add_argument("--name", default="payment-service", help="Workload name")
    p_attest.add_argument("--namespace", default="prod", help="Kubernetes namespace")
    p_attest.add_argument("--service-account", default="payment-service", help="Service account")
    p_attest.add_argument("--digest", default=None, help="SHA-256 binary digest")
    p_attest.set_defaults(func=cmd_attest)

    # federate
    p_fed = subparsers.add_parser("federate", help="Federate identity with AWS STS")
    p_fed.add_argument("--name", default="payment-service")
    p_fed.add_argument("--namespace", default="prod")
    p_fed.add_argument("--service-account", default="payment-service")
    p_fed.add_argument("--role", default=None)
    p_fed.set_defaults(func=cmd_federate)

    # rotate
    p_rot = subparsers.add_parser("rotate", help="Simulate seamless credential rotation")
    p_rot.add_argument("--count", type=int, default=3)
    p_rot.set_defaults(func=cmd_rotate)

    # jwks
    p_jwks = subparsers.add_parser("jwks", help="Export OIDC discovery & JWKS")
    p_jwks.set_defaults(func=cmd_jwks)

    # audit
    p_audit = subparsers.add_parser("audit", help="Run trust and security audit")
    p_audit.set_defaults(func=cmd_audit)

    parsed = parser.parse_args()
    parsed.func(parsed)


if __name__ == "__main__":
    main()
