"""Keylime verifier ingestion adapter.

The adapter consumes existing Keylime API responses and maps them into
normalized claims.  It does not verify TPM evidence itself; Keylime remains the
TPM/vTPM verifier of record.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from keylemon.models import CompositeLevel, Decision, EndpointDescriptor, NormalizedClaims, TPMType
from keylemon.signing import ClaimSigner


@dataclass(slots=True)
class KeylimeClient:
    base_url: str
    signer: ClaimSigner
    verifier_id: str = "keylime_tpm"
    timeout: float = 5.0

    def get_latest_attestation(self, agent_id: str) -> dict[str, Any]:
        url = f"{self.base_url.rstrip('/')}/v3/agents/{agent_id}/attestations/latest"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"Keylime latest attestation request failed: HTTP {exc.code}") from exc

    def normalize_latest(
        self,
        *,
        subject: EndpointDescriptor,
        agent_id: str,
        policy_id: str,
        nonce: str,
        bound_public_key_hash: str,
        validity: timedelta,
        response: dict[str, Any] | None = None,
        tpm_type: TPMType = TPMType.UNKNOWN,
    ):
        raw = response if response is not None else self.get_latest_attestation(agent_id)
        data = raw.get("data", raw)
        attributes = data.get("attributes", data)
        evaluation = attributes.get("evaluation") or raw.get("evaluation")
        evidence = attributes.get("evidence", raw.get("evidence", [])) or []

        claims = NormalizedClaims.minimal(
            subject=subject,
            evidence_type="tpm_quote",
            verifier_id=self.verifier_id,
            policy_id=policy_id,
            nonce=nonce,
            bound_public_key_hash=bound_public_key_hash,
            validity=validity,
        )
        claims.tpm_present = True
        claims.tpm_type = tpm_type
        claims.tpm_ak_fingerprint = self._find_ak_fingerprint(evidence, raw)
        claims.tpm_ek_cert_status = raw.get("tpm_ek_cert_status")
        claims.pcr_policy_ok = evaluation == "pass"
        claims.measured_boot_ok = self._evidence_present(evidence, "uefi_log") if evidence else None
        claims.ima_runtime_ok = self._evidence_present(evidence, "ima_log") if evidence else None
        claims.pcr_selection = self._pcr_selection(evidence)
        claims.composite_attestation_level = (
            CompositeLevel.HARDWARE_TPM if tpm_type == TPMType.PHYSICAL else CompositeLevel.CSP_ASSERTED
        )
        claims.final_authorization_decision = Decision.ALLOW if evaluation == "pass" else Decision.DENY
        claims.raw = {"keylime": raw}
        return self.signer.sign(claims)

    @staticmethod
    def _evidence_present(evidence: list[dict[str, Any]], evidence_type: str) -> bool:
        return any(item.get("evidence_type") == evidence_type for item in evidence)

    @staticmethod
    def _pcr_selection(evidence: list[dict[str, Any]]) -> dict[str, Any] | None:
        for item in evidence:
            if item.get("evidence_type") != "tpm_quote":
                continue
            meta = item.get("data", {}).get("meta", {})
            if "pcrs" in meta:
                return meta["pcrs"]
        return None

    @staticmethod
    def _find_ak_fingerprint(evidence: list[dict[str, Any]], raw: dict[str, Any]) -> str | None:
        ak = raw.get("ak_tpm") or raw.get("aik_tpm")
        for item in evidence:
            for key in item.get("capabilities", {}).get("certification_keys", []) or []:
                ak = key.get("public") or ak
        if not ak:
            return None
        if isinstance(ak, str):
            ak_bytes = ak.encode("utf-8")
        else:
            ak_bytes = bytes(ak)
        return hashlib.sha256(ak_bytes).hexdigest()

