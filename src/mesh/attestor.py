"""Workload and Node Attestor implementation."""

import hashlib
from typing import Dict, Optional, Set
from .models import AttestationEvidence, SpiffeId


class AttestationError(Exception):
    """Raised when workload fails kernel or container attestation."""
    pass


class WorkloadAttestor:
    """Verifies workload authenticity using cgroup, namespace, and binary fingerprinting."""

    def __init__(self, trust_domain: str = "prod.aws.internal"):
        self.trust_domain = trust_domain
        # Whitelisted binary digests: name -> expected_sha256
        self.approved_fingerprints: Dict[str, str] = {
            "payment-service": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "audit-collector": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "finops-agent": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            "data-pipeline": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        }
        self.allowed_namespaces: Set[str] = {"prod", "security", "finops", "core"}

    def register_workload(self, name: str, expected_sha256: str) -> None:
        self.approved_fingerprints[name] = expected_sha256

    def attest(self, evidence: AttestationEvidence) -> SpiffeId:
        """Attest kernel/container evidence and generate valid SPIFFE ID."""
        # 1. Namespace verification
        if evidence.namespace not in self.allowed_namespaces:
            raise AttestationError(
                f"Untrusted namespace '{evidence.namespace}'. Allowed: {sorted(self.allowed_namespaces)}"
            )

        # 2. Cgroup structure verification
        if not evidence.cgroup_path or "kubepods" not in evidence.cgroup_path:
            raise AttestationError(
                f"Invalid cgroup hierarchy '{evidence.cgroup_path}'. Must be within kubepods slice."
            )

        # 3. Non-root container check
        if evidence.container_uid == 0:
            raise AttestationError(
                "Attestation rejected: Workload running as root (UID 0) violates zero-trust baseline."
            )

        # 4. Binary digest verification if registered
        if evidence.workload_name in self.approved_fingerprints:
            expected_digest = self.approved_fingerprints[evidence.workload_name]
            if evidence.binary_sha256 != expected_digest:
                raise AttestationError(
                    f"Integrity check failed for '{evidence.workload_name}'. "
                    f"Expected digest {expected_digest[:12]}..., got {evidence.binary_sha256[:12]}..."
                )

        # Workload passed all attestation checks
        return SpiffeId.from_k8s(
            trust_domain=self.trust_domain,
            namespace=evidence.namespace,
            service_account=evidence.service_account,
        )
