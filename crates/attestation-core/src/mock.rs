use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::{
    AttestationError, AttestationResult, CapabilityType, CompositeAttestationLevel, Decision,
    Evidence, EvidenceType, EvidenceVerifier, NormalizedClaims, SessionBinding, TcbStatus,
    TeeClaims, TeeType, TpmClaims, TpmType, VerifierId,
};

#[derive(Clone, Debug)]
pub struct MockTpmVerifier {
    known_aks: BTreeSet<String>,
    expected_pcrs: BTreeMap<u32, String>,
}

impl Default for MockTpmVerifier {
    fn default() -> Self {
        Self {
            known_aks: BTreeSet::from(["ak-good".to_owned()]),
            expected_pcrs: BTreeMap::from([(10, "good-pcr-10".to_owned())]),
        }
    }
}

impl MockTpmVerifier {
    pub fn new(known_aks: BTreeSet<String>, expected_pcrs: BTreeMap<u32, String>) -> Self {
        Self {
            known_aks,
            expected_pcrs,
        }
    }
}

impl EvidenceVerifier for MockTpmVerifier {
    fn verifier_id(&self) -> VerifierId {
        VerifierId("mock-tpm-verifier".to_owned())
    }

    fn evidence_type(&self) -> EvidenceType {
        EvidenceType::MockTpm
    }

    fn verify(
        &self,
        evidence: &Evidence,
        expected: &SessionBinding,
    ) -> Result<AttestationResult, AttestationError> {
        let Evidence::MockTpm(evidence) = evidence else {
            return Err(AttestationError::UnsupportedEvidence);
        };
        let now = Utc::now();
        if evidence.expires_at <= now {
            return Err(AttestationError::Expired);
        }
        if evidence.nonce != expected.nonce {
            return Err(AttestationError::NonceMismatch);
        }
        if evidence.public_key_hash != expected.public_key_hash {
            return Err(AttestationError::PublicKeyBindingMismatch);
        }
        if evidence.quote_signature_marker != "mock-tpm-quote-ok" {
            return Err(AttestationError::InvalidQuoteMarker);
        }
        if !self.known_aks.contains(&evidence.ak_fingerprint) {
            return Err(AttestationError::UnknownAk);
        }
        for (index, expected_value) in &self.expected_pcrs {
            if evidence.pcr_values.get(index) != Some(expected_value) {
                return Err(AttestationError::BadPcr(*index));
            }
        }
        if !evidence.measured_boot_ok {
            return Err(AttestationError::MeasuredBootFailed);
        }
        if !evidence.ima_runtime_ok {
            return Err(AttestationError::ImaFailed);
        }

        Ok(AttestationResult {
            claims: NormalizedClaims {
                subject_id: evidence.subject_id.clone(),
                capabilities: vec![CapabilityType::PhysicalTpm],
                evidence_type: EvidenceType::MockTpm,
                verifier_id: self.verifier_id(),
                issued_at: evidence.issued_at,
                expires_at: evidence.expires_at,
                freshness_nonce: evidence.nonce.clone(),
                public_key_hash: evidence.public_key_hash.clone(),
                transcript_hash: expected.transcript_hash.clone(),
                tpm: Some(TpmClaims {
                    tpm_present: true,
                    tpm_type: TpmType::Physical,
                    ek_fingerprint: evidence.ek_fingerprint.clone(),
                    ak_fingerprint: evidence.ak_fingerprint.clone(),
                    ek_cert_status: "accepted".to_owned(),
                    pcr_policy_ok: true,
                    pcr_selection: evidence.pcr_selection.clone(),
                    measured_boot_ok: true,
                    ima_runtime_ok: true,
                }),
                tee: None,
                composite_attestation_level: CompositeAttestationLevel::HardwareTpm,
                final_decision: Decision::Allow,
                raw_summary: "demo mock TPM evidence accepted".to_owned(),
            },
            failure_reason: None,
        })
    }
}

#[derive(Clone, Debug)]
pub struct MockTeeVerifier {
    allowed_types: BTreeSet<TeeType>,
    allowed_measurements: BTreeSet<String>,
    allowed_tcb: BTreeSet<TcbStatus>,
}

impl Default for MockTeeVerifier {
    fn default() -> Self {
        Self {
            allowed_types: BTreeSet::from([TeeType::MockSnp, TeeType::MockTdx, TeeType::MockSgx]),
            allowed_measurements: BTreeSet::from(["tee-good-measurement".to_owned()]),
            allowed_tcb: BTreeSet::from([TcbStatus::UpToDate, TcbStatus::Acceptable]),
        }
    }
}

impl MockTeeVerifier {
    pub fn expected_report_data(nonce: &str, public_key_hash: &str) -> String {
        let digest = Sha256::digest(format!("{nonce}:{public_key_hash}").as_bytes());
        hex::encode(digest)
    }
}

impl EvidenceVerifier for MockTeeVerifier {
    fn verifier_id(&self) -> VerifierId {
        VerifierId("mock-tee-verifier".to_owned())
    }

    fn evidence_type(&self) -> EvidenceType {
        EvidenceType::MockTee
    }

    fn verify(
        &self,
        evidence: &Evidence,
        expected: &SessionBinding,
    ) -> Result<AttestationResult, AttestationError> {
        let Evidence::MockTee(evidence) = evidence else {
            return Err(AttestationError::UnsupportedEvidence);
        };
        let now = Utc::now();
        if evidence.expires_at <= now {
            return Err(AttestationError::Expired);
        }
        if evidence.nonce != expected.nonce {
            return Err(AttestationError::NonceMismatch);
        }
        if evidence.public_key_hash != expected.public_key_hash {
            return Err(AttestationError::PublicKeyBindingMismatch);
        }
        if !self.allowed_types.contains(&evidence.tee_type) {
            return Err(AttestationError::TeeTypeDenied);
        }
        if evidence.debug {
            return Err(AttestationError::TeeDebugEnabled);
        }
        if !self.allowed_measurements.contains(&evidence.measurement) {
            return Err(AttestationError::TeeMeasurementDenied);
        }
        if !self.allowed_tcb.contains(&evidence.tcb_status) {
            return Err(AttestationError::TeeTcbDenied);
        }
        let expected_report_data =
            Self::expected_report_data(&expected.nonce.0, &expected.public_key_hash);
        if evidence.report_data != expected_report_data {
            return Err(AttestationError::TeeReportDataMismatch);
        }

        Ok(AttestationResult {
            claims: NormalizedClaims {
                subject_id: evidence.subject_id.clone(),
                capabilities: vec![CapabilityType::Tee],
                evidence_type: EvidenceType::MockTee,
                verifier_id: self.verifier_id(),
                issued_at: evidence.issued_at,
                expires_at: evidence.expires_at,
                freshness_nonce: evidence.nonce.clone(),
                public_key_hash: evidence.public_key_hash.clone(),
                transcript_hash: expected.transcript_hash.clone(),
                tpm: None,
                tee: Some(TeeClaims {
                    tee_present: true,
                    tee_type: evidence.tee_type,
                    measurement: evidence.measurement.clone(),
                    tcb_status: evidence.tcb_status,
                    debug_disabled: !evidence.debug,
                    instance_id: evidence.instance_id.clone(),
                    report_data_hash: evidence.report_data.clone(),
                }),
                composite_attestation_level: CompositeAttestationLevel::TeeBacked,
                final_decision: Decision::Allow,
                raw_summary: "demo mock TEE evidence accepted".to_owned(),
            },
            failure_reason: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{Duration, Utc};

    use super::*;
    use crate::{MockTeeEvidence, MockTpmEvidence, Nonce, SubjectId};

    fn binding() -> SessionBinding {
        SessionBinding {
            nonce: Nonce("n".to_owned()),
            public_key_hash: "pkh".to_owned(),
            transcript_hash: None,
        }
    }

    #[test]
    fn mock_tpm_success() {
        let now = Utc::now();
        let evidence = Evidence::MockTpm(MockTpmEvidence {
            subject_id: SubjectId("a".to_owned()),
            ek_fingerprint: "ek".to_owned(),
            ak_fingerprint: "ak-good".to_owned(),
            pcr_selection: vec![10],
            pcr_values: BTreeMap::from([(10, "good-pcr-10".to_owned())]),
            measured_boot_ok: true,
            ima_runtime_ok: true,
            nonce: Nonce("n".to_owned()),
            public_key_hash: "pkh".to_owned(),
            issued_at: now,
            expires_at: now + Duration::seconds(60),
            quote_signature_marker: "mock-tpm-quote-ok".to_owned(),
        });
        let result = MockTpmVerifier::default()
            .verify(&evidence, &binding())
            .expect("mock TPM evidence should verify");
        assert_eq!(result.claims.final_decision, Decision::Allow);
    }

    #[test]
    fn mock_tee_rejects_debug() {
        let now = Utc::now();
        let evidence = Evidence::MockTee(MockTeeEvidence {
            subject_id: SubjectId("b".to_owned()),
            tee_type: TeeType::MockSnp,
            measurement: "tee-good-measurement".to_owned(),
            tcb_status: TcbStatus::UpToDate,
            debug: true,
            instance_id: "tee-b".to_owned(),
            report_data: MockTeeVerifier::expected_report_data("n", "pkh"),
            nonce: Nonce("n".to_owned()),
            public_key_hash: "pkh".to_owned(),
            issued_at: now,
            expires_at: now + Duration::seconds(60),
        });
        let err = MockTeeVerifier::default()
            .verify(&evidence, &binding())
            .expect_err("debug TEE evidence should fail");
        assert!(matches!(err, AttestationError::TeeDebugEnabled));
    }
}
