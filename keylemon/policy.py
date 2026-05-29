"""Policy model and evaluator for composed attestation results."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Any

import yaml

from keylemon.models import AttestationResult, CapabilityType, Decision, NormalizedClaims, utc_now


@dataclass(slots=True)
class PolicyDecision:
    decision: Decision
    reasons: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.decision in (Decision.ALLOW, Decision.DEGRADED)


@dataclass(slots=True)
class AttestationPolicy:
    policy_id: str
    raw: dict[str, Any]
    policy_version: str = "1"

    @classmethod
    def from_yaml(cls, data: str) -> "AttestationPolicy":
        raw = yaml.safe_load(data) or {}
        return cls(policy_id=raw["policy_id"], raw=raw, policy_version=str(raw.get("policy_version", "1")))

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "AttestationPolicy":
        return cls(policy_id=raw["policy_id"], raw=raw, policy_version=str(raw.get("policy_version", "1")))

    @property
    def max_evidence_age_seconds(self) -> int:
        return int(self.raw.get("defaults", {}).get("max_evidence_age_seconds", 60))

    @property
    def require_session_binding(self) -> bool:
        return bool(self.raw.get("defaults", {}).get("require_session_binding", True))


class PolicyEngine:
    def evaluate(
        self,
        policy: AttestationPolicy,
        local: list[AttestationResult],
        remote: list[AttestationResult],
        *,
        action: str = "connect",
    ) -> PolicyDecision:
        reasons: list[str] = []

        local_claims = [item.claims for item in local]
        remote_claims = [item.claims for item in remote]

        self._evaluate_side("local_endpoint", policy, local_claims, reasons)
        self._evaluate_side("remote_endpoint", policy, remote_claims, reasons)

        mutual = policy.raw.get("mutual", {})
        if mutual.get("both_sides_attested") and (not local_claims or not remote_claims):
            reasons.append("mutual policy requires both local and remote attestation results")

        if policy.require_session_binding or mutual.get("bind_to_current_session"):
            for side, claims in (("local", local_claims), ("remote", remote_claims)):
                for claim in claims:
                    if not claim.bound_public_key_hash:
                        reasons.append(f"{side} result for {claim.subject_id} is not bound to a public key")

        for claims in local_claims + remote_claims:
            if claims.expired:
                reasons.append(f"result for {claims.subject_id} is expired")
            age = (utc_now() - claims.attestation_time).total_seconds()
            if age > policy.max_evidence_age_seconds:
                reasons.append(f"result for {claims.subject_id} exceeds max evidence age")

        if reasons:
            degraded = self._degraded_allowed(policy, local_claims + remote_claims, action)
            return PolicyDecision(Decision.DEGRADED if degraded else Decision.DENY, reasons)

        return PolicyDecision(Decision.ALLOW, ["policy satisfied"])

    def _evaluate_side(
        self,
        side: str,
        policy: AttestationPolicy,
        claims: list[NormalizedClaims],
        reasons: list[str],
    ) -> None:
        spec = policy.raw.get(side, {})
        if not spec:
            return

        require_any = {CapabilityType(item).value for item in spec.get("require_any", [])}
        if require_any and not any(require_any.intersection(set(claim.attestation_capabilities)) for claim in claims):
            reasons.append(f"{side} lacks required capability from {sorted(require_any)}")

        tee_spec = spec.get("tee", {})
        if tee_spec and any(claim.tee_present for claim in claims):
            for claim in (claim for claim in claims if claim.tee_present):
                permitted = tee_spec.get("permitted_types")
                if permitted and claim.tee_type not in permitted:
                    reasons.append(f"{side} TEE type {claim.tee_type!r} is not permitted")
                if tee_spec.get("debug_disabled") and claim.tee_debug_disabled is not True:
                    reasons.append(f"{side} TEE debug mode is not disabled")
                allowlist = tee_spec.get("measurements_allowlist")
                if allowlist and claim.tee_measurement not in allowlist:
                    reasons.append(f"{side} TEE measurement is not allowlisted")
                acceptable = tee_spec.get("acceptable_tcb_status")
                if acceptable and claim.tee_tcb_status not in acceptable:
                    reasons.append(f"{side} TEE TCB status {claim.tee_tcb_status!r} is not acceptable")

        tpm_spec = spec.get("tpm", {})
        if tpm_spec and any(claim.tpm_present for claim in claims):
            for claim in (claim for claim in claims if claim.tpm_present):
                required_mb = tpm_spec.get("require_measured_boot_policy")
                if required_mb and (claim.measured_boot_ok is not True or claim.measured_boot_policy_id != required_mb):
                    reasons.append(f"{side} measured boot policy {required_mb!r} is not satisfied")
                required_ima = tpm_spec.get("require_ima_policy")
                if required_ima and (claim.ima_runtime_ok is not True or claim.ima_policy_id != required_ima):
                    reasons.append(f"{side} IMA policy {required_ima!r} is not satisfied")

    def _degraded_allowed(self, policy: AttestationPolicy, claims: list[NormalizedClaims], action: str) -> bool:
        spec = policy.raw.get("degraded_mode", {})
        if not spec:
            return False
        denied_actions = set(spec.get("denied_actions", []))
        if action in denied_actions:
            return False
        allowed_subjects = spec.get("allowed_subjects", [])
        return any(any(fnmatch(claim.subject_id, pattern) for pattern in allowed_subjects) for claim in claims)

