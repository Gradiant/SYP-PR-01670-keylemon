use std::collections::BTreeMap;

use anyhow::{Result, anyhow};
use attestation_broker::Broker;
use attestation_core::{
    Decision, Evidence, MockTeeEvidence, MockTeeVerifier, MockTpmEvidence, Nonce, SessionBinding,
    SubjectId, TcbStatus, TeeType,
};
use chrono::{Duration, Utc};
use policy_engine::Policy;
use session_binding::EphemeralKeypair;
use wrapper::TrafficGate;

#[derive(Clone, Copy, Debug)]
pub enum ScenarioKind {
    Allowed,
    ImaFail,
    TeeDebug,
    BadMeasurement,
    Replay,
    SessionBindingFail,
    DegradedMode,
}

pub fn run_scenario(kind: ScenarioKind) -> Result<String> {
    let policy_yaml = match kind {
        ScenarioKind::DegradedMode => include_str!("../configs/policies/degraded-mode.yaml"),
        _ => include_str!("../configs/policies/require-mutual-attestation.yaml"),
    };
    let policy = Policy::from_yaml(policy_yaml)?;
    let broker = Broker::with_mock_backends(policy);
    let now = Utc::now();
    let local_key = EphemeralKeypair::generate();
    let remote_key = EphemeralKeypair::generate();
    let local_binding = SessionBinding {
        nonce: Nonce("local-demo-nonce".to_owned()),
        public_key_hash: local_key.public_key_hash(),
        transcript_hash: None,
    };
    let remote_binding = SessionBinding {
        nonce: Nonce("remote-demo-nonce".to_owned()),
        public_key_hash: remote_key.public_key_hash(),
        transcript_hash: None,
    };

    if matches!(kind, ScenarioKind::DegradedMode) {
        let decision = broker.decide(&[], &[]);
        let gate = TrafficGate::new(true);
        let status = if gate.forward_simulated(&decision, b"demo").is_ok() {
            "decision=degraded"
        } else {
            "decision=deny"
        };
        return Ok(format!("{status} reason={}", decision.reason));
    }

    let tpm_evidence = Evidence::MockTpm(MockTpmEvidence {
        subject_id: SubjectId("endpoint-a".to_owned()),
        ek_fingerprint: "ek-good".to_owned(),
        ak_fingerprint: "ak-good".to_owned(),
        pcr_selection: vec![10],
        pcr_values: BTreeMap::from([(10, "good-pcr-10".to_owned())]),
        measured_boot_ok: true,
        ima_runtime_ok: !matches!(kind, ScenarioKind::ImaFail),
        nonce: local_binding.nonce.clone(),
        public_key_hash: local_binding.public_key_hash.clone(),
        issued_at: now,
        expires_at: if matches!(kind, ScenarioKind::Replay) {
            now - Duration::seconds(1)
        } else {
            now + Duration::seconds(60)
        },
        quote_signature_marker: "mock-tpm-quote-ok".to_owned(),
    });
    let report_public_key_hash = if matches!(kind, ScenarioKind::SessionBindingFail) {
        "wrong-public-key-hash".to_owned()
    } else {
        remote_binding.public_key_hash.clone()
    };
    let tee_evidence = Evidence::MockTee(MockTeeEvidence {
        subject_id: SubjectId("endpoint-b".to_owned()),
        tee_type: TeeType::MockSnp,
        measurement: if matches!(kind, ScenarioKind::BadMeasurement) {
            "bad-measurement".to_owned()
        } else {
            "tee-good-measurement".to_owned()
        },
        tcb_status: TcbStatus::UpToDate,
        debug: matches!(kind, ScenarioKind::TeeDebug),
        instance_id: "tee-b".to_owned(),
        report_data: MockTeeVerifier::expected_report_data(
            &remote_binding.nonce.0,
            &report_public_key_hash,
        ),
        nonce: remote_binding.nonce.clone(),
        public_key_hash: report_public_key_hash,
        issued_at: now,
        expires_at: now + Duration::seconds(60),
    });

    let local_result = broker
        .verify_evidence(&tpm_evidence, &local_binding)
        .map_err(|error| anyhow!(error.to_string()));
    let remote_result = broker
        .verify_evidence(&tee_evidence, &remote_binding)
        .map_err(|error| anyhow!(error.to_string()));

    if let Err(error) = &local_result {
        return Ok(format!("decision=deny reason={error}"));
    }
    if let Err(error) = &remote_result {
        return Ok(format!("decision=deny reason={error}"));
    }

    let local_result = local_result?;
    let remote_result = remote_result?;
    let decision = broker.decide(
        std::slice::from_ref(&local_result),
        std::slice::from_ref(&remote_result),
    );
    if decision.decision == Decision::Allow {
        let _token = broker.issue_token(remote_result, remote_binding.public_key_hash)?;
        TrafficGate::default().forward_simulated(&decision, b"demo")?;
    }
    Ok(format!(
        "decision={} reason={}",
        match decision.decision {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::Degraded => "degraded",
        },
        decision.reason
    ))
}
