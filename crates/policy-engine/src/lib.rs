use std::collections::BTreeMap;

use attestation_core::{
    AttestationResult, CapabilityType, Decision, PolicyDecision, TcbStatus, TeeType,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    pub policy_id: String,
    pub max_evidence_age_seconds: i64,
    pub require_session_binding: bool,
    #[serde(default)]
    pub local_endpoint: EndpointPolicy,
    #[serde(default)]
    pub remote_endpoint: EndpointPolicy,
    #[serde(default)]
    pub mutual: MutualPolicy,
    #[serde(default)]
    pub degraded_mode: DegradedMode,
}

impl Policy {
    pub fn from_yaml(input: &str) -> Result<Self, PolicyError> {
        Ok(serde_yaml::from_str(input)?)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EndpointPolicy {
    #[serde(default)]
    pub require_any: Vec<CapabilityType>,
    #[serde(default)]
    pub tpm: TpmPolicy,
    #[serde(default)]
    pub tee: TeePolicy,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TpmPolicy {
    #[serde(default)]
    pub require_measured_boot: bool,
    #[serde(default)]
    pub require_ima: bool,
    #[serde(default)]
    pub required_pcrs: BTreeMap<u32, String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TeePolicy {
    #[serde(default)]
    pub permitted_types: Vec<TeeType>,
    #[serde(default)]
    pub debug_disabled: bool,
    #[serde(default)]
    pub measurements_allowlist: Vec<String>,
    #[serde(default)]
    pub acceptable_tcb_status: Vec<TcbStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MutualPolicy {
    pub both_sides_attested: bool,
}

impl Default for MutualPolicy {
    fn default() -> Self {
        Self {
            both_sides_attested: true,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DegradedMode {
    #[serde(default)]
    pub allow_unauthenticated_subjects: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct PolicyEngine;

impl PolicyEngine {
    pub fn evaluate(
        &self,
        policy: &Policy,
        local_results: &[AttestationResult],
        remote_results: &[AttestationResult],
        now: DateTime<Utc>,
    ) -> PolicyDecision {
        if policy.mutual.both_sides_attested
            && (local_results.is_empty() || remote_results.is_empty())
        {
            return self.degraded_or_deny(policy, "mutual_attestation_missing", local_results);
        }

        if let Some(reason) = validate_side(policy, &policy.local_endpoint, local_results, now) {
            return self.degraded_or_deny(policy, &reason, local_results);
        }
        if let Some(reason) = validate_side(policy, &policy.remote_endpoint, remote_results, now) {
            return self.degraded_or_deny(policy, &reason, remote_results);
        }

        PolicyDecision {
            decision: Decision::Allow,
            reason: "policy_satisfied".to_owned(),
        }
    }

    fn degraded_or_deny(
        &self,
        policy: &Policy,
        reason: &str,
        results: &[AttestationResult],
    ) -> PolicyDecision {
        let wildcard_degraded = policy
            .degraded_mode
            .allow_unauthenticated_subjects
            .iter()
            .any(|subject| subject == "*");
        let degraded = wildcard_degraded
            || results.iter().any(|result| {
                policy
                    .degraded_mode
                    .allow_unauthenticated_subjects
                    .iter()
                    .any(|subject| subject == &result.claims.subject_id.0 || subject == "*")
            });
        PolicyDecision {
            decision: if degraded {
                Decision::Degraded
            } else {
                Decision::Deny
            },
            reason: reason.to_owned(),
        }
    }
}

fn validate_side(
    policy: &Policy,
    endpoint: &EndpointPolicy,
    results: &[AttestationResult],
    now: DateTime<Utc>,
) -> Option<String> {
    for result in results {
        if result.failure_reason.is_some() || result.claims.final_decision != Decision::Allow {
            return Some("failed_attestation_result".to_owned());
        }
        if result.is_expired(now) {
            return Some("expired_attestation_result".to_owned());
        }
        if (now - result.claims.issued_at).num_seconds() > policy.max_evidence_age_seconds {
            return Some("stale_attestation_result".to_owned());
        }
        if policy.require_session_binding && result.claims.public_key_hash.is_empty() {
            return Some("missing_session_binding".to_owned());
        }
    }

    if !endpoint.require_any.is_empty() {
        let has_required = results.iter().any(|result| {
            result
                .claims
                .capabilities
                .iter()
                .any(|capability| endpoint.require_any.contains(capability))
        });
        if !has_required {
            return Some("required_capability_missing".to_owned());
        }
    }

    for result in results {
        if let Some(tpm) = &result.claims.tpm {
            if endpoint.tpm.require_measured_boot && !tpm.measured_boot_ok {
                return Some("measured_boot_failed".to_owned());
            }
            if endpoint.tpm.require_ima && !tpm.ima_runtime_ok {
                return Some("ima_failed".to_owned());
            }
        }
        if let Some(tee) = &result.claims.tee {
            if endpoint.tee.debug_disabled && !tee.debug_disabled {
                return Some("tee_debug_enabled".to_owned());
            }
            if !endpoint.tee.permitted_types.is_empty()
                && !endpoint.tee.permitted_types.contains(&tee.tee_type)
            {
                return Some("tee_type_denied".to_owned());
            }
            if !endpoint.tee.measurements_allowlist.is_empty()
                && !endpoint
                    .tee
                    .measurements_allowlist
                    .contains(&tee.measurement)
            {
                return Some("tee_measurement_denied".to_owned());
            }
            if !endpoint.tee.acceptable_tcb_status.is_empty()
                && !endpoint.tee.acceptable_tcb_status.contains(&tee.tcb_status)
            {
                return Some("tee_tcb_denied".to_owned());
            }
        }
    }
    None
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("invalid policy yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

#[cfg(test)]
mod tests {
    use attestation_core::{NormalizedClaims, SubjectId, VerifierId};
    use chrono::Duration;

    use super::*;

    fn result(capability: CapabilityType) -> AttestationResult {
        let now = Utc::now();
        AttestationResult {
            claims: NormalizedClaims {
                subject_id: SubjectId("subject".to_owned()),
                capabilities: vec![capability],
                evidence_type: attestation_core::EvidenceType::NoHardware,
                verifier_id: VerifierId("test".to_owned()),
                issued_at: now,
                expires_at: now + Duration::seconds(60),
                freshness_nonce: attestation_core::Nonce("n".to_owned()),
                public_key_hash: "pkh".to_owned(),
                transcript_hash: None,
                tpm: None,
                tee: None,
                composite_attestation_level: attestation_core::CompositeAttestationLevel::Software,
                final_decision: Decision::Allow,
                raw_summary: "test".to_owned(),
            },
            failure_reason: None,
        }
    }

    #[test]
    fn denies_missing_required_capability() {
        let policy = Policy::from_yaml(
            r#"
policy_id: test
max_evidence_age_seconds: 60
require_session_binding: true
local_endpoint:
  require_any: [physical_tpm]
remote_endpoint:
  require_any: [tee]
"#,
        )
        .unwrap();
        let decision = PolicyEngine.evaluate(
            &policy,
            &[result(CapabilityType::PhysicalTpm)],
            &[result(CapabilityType::None)],
            Utc::now(),
        );
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason, "required_capability_missing");
    }
}
