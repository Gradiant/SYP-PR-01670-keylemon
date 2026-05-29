"""Normalized attestation data model.

The model intentionally keeps TPM, vTPM, and TEE semantics separate.  The broker
uses these structures as the stable interface between technology-specific
verifiers and relying-party policy decisions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any


class CapabilityType(StrEnum):
    NONE = "none"
    PHYSICAL_TPM = "physical_tpm"
    VTPM = "vtpm"
    TEE = "tee"
    TEE_BACKED_VTPM = "tee_backed_vtpm"
    PHYSICAL_TPM_TEE = "physical_tpm_tee"
    EXTENSION = "extension"


class CompositionRole(StrEnum):
    SUFFICIENT = "sufficient"
    REQUIRES_COMPOSITION = "requires_composition"
    INFORMATIONAL = "informational"


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    DEGRADED = "degraded"


class TPMType(StrEnum):
    PHYSICAL = "physical"
    VIRTUAL = "virtual"
    EMULATED = "emulated"
    UNKNOWN = "unknown"


class CompositeLevel(StrEnum):
    NONE = "none"
    SOFTWARE = "software"
    CSP_ASSERTED = "csp_asserted"
    TEE_BACKED = "tee_backed"
    HARDWARE_TPM = "hardware_tpm"
    COMPOSED = "composed"


def utc_now() -> datetime:
    return datetime.now(UTC)


def isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_time(value: str | datetime | None) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


@dataclass(slots=True)
class AttestationCapability:
    type: CapabilityType
    evidence_types: list[str]
    trust_anchor: str
    verifier: str
    freshness: str
    session_binding: list[str] = field(default_factory=list)
    composition_role: CompositionRole = CompositionRole.INFORMATIONAL
    meta: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttestationCapability":
        return cls(
            type=CapabilityType(data["type"]),
            evidence_types=list(data.get("evidence_types", [])),
            trust_anchor=data.get("trust_anchor", "none"),
            verifier=data.get("verifier", "unknown"),
            freshness=data.get("freshness", "nonce"),
            session_binding=list(data.get("session_binding", [])),
            composition_role=CompositionRole(data.get("composition_role", "informational")),
            meta=dict(data.get("meta", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        output = asdict(self)
        output["type"] = self.type.value
        output["composition_role"] = self.composition_role.value
        return output


@dataclass(slots=True)
class EndpointDescriptor:
    subject_id: str
    subject_type: str
    platform_id: str
    capabilities: list[AttestationCapability]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EndpointDescriptor":
        return cls(
            subject_id=data["subject_id"],
            subject_type=data.get("subject_type", "node"),
            platform_id=data.get("platform_id", data["subject_id"]),
            capabilities=[AttestationCapability.from_dict(item) for item in data.get("capabilities", [])],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_id": self.subject_id,
            "subject_type": self.subject_type,
            "platform_id": self.platform_id,
            "capabilities": [item.to_dict() for item in self.capabilities],
        }


@dataclass(slots=True)
class NormalizedClaims:
    subject_id: str
    subject_type: str
    platform_id: str
    attestation_capabilities: list[str]
    evidence_type: str
    verifier_id: str
    policy_id: str
    policy_version: str
    attestation_time: datetime
    result_expiry: datetime
    freshness_nonce: str
    bound_public_key_hash: str
    session_transcript_hash: str | None = None
    issuer: str = "keylemon"
    key_id: str = "default"
    tpm_present: bool = False
    tpm_type: TPMType = TPMType.UNKNOWN
    tpm_ek_fingerprint: str | None = None
    tpm_ak_fingerprint: str | None = None
    tpm_ek_cert_status: str | None = None
    pcr_policy_ok: bool | None = None
    pcr_selection: dict[str, Any] | None = None
    measured_boot_ok: bool | None = None
    measured_boot_policy_id: str | None = None
    ima_runtime_ok: bool | None = None
    ima_policy_id: str | None = None
    tee_present: bool = False
    tee_type: str | None = None
    tee_vendor: str | None = None
    tee_measurement: str | None = None
    tee_tcb_status: str | None = None
    tee_debug_disabled: bool | None = None
    tee_instance_id: str | None = None
    tee_report_data_hash: str | None = None
    vtpm_present: bool = False
    vtpm_bound_to_tee: bool | None = None
    vtpm_instance_binding_ok: bool | None = None
    composite_attestation_level: CompositeLevel = CompositeLevel.NONE
    final_authorization_decision: Decision = Decision.DENY
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def minimal(
        cls,
        *,
        subject: EndpointDescriptor,
        evidence_type: str,
        verifier_id: str,
        policy_id: str,
        nonce: str,
        bound_public_key_hash: str,
        validity: timedelta,
    ) -> "NormalizedClaims":
        now = utc_now()
        return cls(
            subject_id=subject.subject_id,
            subject_type=subject.subject_type,
            platform_id=subject.platform_id,
            attestation_capabilities=[cap.type.value for cap in subject.capabilities],
            evidence_type=evidence_type,
            verifier_id=verifier_id,
            policy_id=policy_id,
            policy_version="1",
            attestation_time=now,
            result_expiry=now + validity,
            freshness_nonce=nonce,
            bound_public_key_hash=bound_public_key_hash,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NormalizedClaims":
        converted = dict(data)
        converted["attestation_time"] = parse_time(converted["attestation_time"])
        converted["result_expiry"] = parse_time(converted["result_expiry"])
        converted["tpm_type"] = TPMType(converted.get("tpm_type", TPMType.UNKNOWN))
        converted["composite_attestation_level"] = CompositeLevel(
            converted.get("composite_attestation_level", CompositeLevel.NONE)
        )
        converted["final_authorization_decision"] = Decision(converted.get("final_authorization_decision", Decision.DENY))
        return cls(**converted)

    def to_dict(self) -> dict[str, Any]:
        output = asdict(self)
        output["attestation_time"] = isoformat(self.attestation_time)
        output["result_expiry"] = isoformat(self.result_expiry)
        output["tpm_type"] = self.tpm_type.value
        output["composite_attestation_level"] = self.composite_attestation_level.value
        output["final_authorization_decision"] = self.final_authorization_decision.value
        return output

    @property
    def expired(self) -> bool:
        return self.result_expiry <= utc_now()


@dataclass(slots=True)
class AttestationResult:
    claims: NormalizedClaims
    signature: str
    signing_alg: str
    key_id: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttestationResult":
        return cls(
            claims=NormalizedClaims.from_dict(data["claims"]),
            signature=data["signature"],
            signing_alg=data.get("signing_alg", "ed25519"),
            key_id=data.get("key_id", "default"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "claims": self.claims.to_dict(),
            "signature": self.signature,
            "signing_alg": self.signing_alg,
            "key_id": self.key_id,
        }

