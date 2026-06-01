use std::{collections::BTreeMap, sync::Arc};

use attestation_core::{
    AttestationError, AttestationResult, Evidence, EvidenceType, EvidenceVerifier, MockTeeVerifier,
    MockTpmVerifier, PolicyDecision, SessionBinding,
};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{Duration, Utc};
use policy_engine::{Policy, PolicyEngine};
use serde::{Deserialize, Serialize};
use session_binding::{SignedAttestationToken, TokenIssuer, generate_nonce};
use thiserror::Error;

#[derive(Clone)]
pub struct Broker {
    policy: Policy,
    policy_engine: PolicyEngine,
    verifiers: BTreeMap<EvidenceType, Arc<dyn EvidenceVerifier>>,
    token_issuer: TokenIssuer,
}

impl Broker {
    pub fn with_mock_backends(policy: Policy) -> Self {
        let mut verifiers: BTreeMap<EvidenceType, Arc<dyn EvidenceVerifier>> = BTreeMap::new();
        verifiers.insert(EvidenceType::MockTpm, Arc::new(MockTpmVerifier::default()));
        verifiers.insert(EvidenceType::MockTee, Arc::new(MockTeeVerifier::default()));
        Self {
            policy,
            policy_engine: PolicyEngine,
            verifiers,
            token_issuer: TokenIssuer::generate(),
        }
    }

    pub fn verify_evidence(
        &self,
        evidence: &Evidence,
        expected: &SessionBinding,
    ) -> Result<AttestationResult, BrokerError> {
        let verifier = self
            .verifiers
            .get(&evidence.evidence_type())
            .ok_or(BrokerError::NoVerifier(evidence.evidence_type()))?;
        Ok(verifier.verify(evidence, expected)?)
    }

    pub fn decide(
        &self,
        local_results: &[AttestationResult],
        remote_results: &[AttestationResult],
    ) -> PolicyDecision {
        self.policy_engine
            .evaluate(&self.policy, local_results, remote_results, Utc::now())
    }

    pub fn issue_token(
        &self,
        result: AttestationResult,
        public_key_hash: String,
    ) -> Result<SignedAttestationToken, BrokerError> {
        Ok(self
            .token_issuer
            .issue(result, public_key_hash, Duration::seconds(60))?)
    }
}

#[derive(Clone)]
pub struct AppState {
    broker: Arc<Broker>,
}

pub fn router(broker: Broker) -> Router {
    Router::new()
        .route("/v1/challenges", post(challenge))
        .route("/v1/evidence", post(evidence))
        .route("/v1/decide", post(decide))
        .route("/v1/tokens", post(token))
        .route("/v1/schemas", get(schemas))
        .with_state(AppState {
            broker: Arc::new(broker),
        })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub public_key_hash: String,
    pub transcript_hash: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub binding: SessionBinding,
}

async fn challenge(Json(request): Json<ChallengeRequest>) -> Json<ChallengeResponse> {
    Json(ChallengeResponse {
        binding: SessionBinding {
            nonce: generate_nonce(),
            public_key_hash: request.public_key_hash,
            transcript_hash: request.transcript_hash,
        },
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EvidenceRequest {
    pub evidence: Evidence,
    pub expected_binding: SessionBinding,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EvidenceResponse {
    pub result: AttestationResult,
}

async fn evidence(
    State(state): State<AppState>,
    Json(request): Json<EvidenceRequest>,
) -> Result<Json<EvidenceResponse>, BrokerError> {
    Ok(Json(EvidenceResponse {
        result: state
            .broker
            .verify_evidence(&request.evidence, &request.expected_binding)?,
    }))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecideRequest {
    pub local_results: Vec<AttestationResult>,
    pub remote_results: Vec<AttestationResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecideResponse {
    pub decision: PolicyDecision,
}

async fn decide(
    State(state): State<AppState>,
    Json(request): Json<DecideRequest>,
) -> Json<DecideResponse> {
    Json(DecideResponse {
        decision: state
            .broker
            .decide(&request.local_results, &request.remote_results),
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenRequest {
    pub result: AttestationResult,
    pub public_key_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub token: SignedAttestationToken,
}

async fn token(
    State(state): State<AppState>,
    Json(request): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, BrokerError> {
    Ok(Json(TokenResponse {
        token: state
            .broker
            .issue_token(request.result, request.public_key_hash)?,
    }))
}

async fn schemas() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "schemas": {
            "challenge": "ChallengeRequest/ChallengeResponse",
            "evidence": "EvidenceRequest/EvidenceResponse",
            "decision": "DecideRequest/DecideResponse",
            "token": "TokenRequest/TokenResponse"
        }
    }))
}

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("no verifier registered for {0:?}")]
    NoVerifier(EvidenceType),
    #[error("attestation verification failed: {0}")]
    Attestation(#[from] AttestationError),
    #[error("token issue failed: {0}")]
    Token(#[from] session_binding::TokenError),
}

impl IntoResponse for BrokerError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::NoVerifier(_) => StatusCode::BAD_REQUEST,
            Self::Attestation(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Token(_) => StatusCode::UNPROCESSABLE_ENTITY,
        };
        (
            status,
            Json(serde_json::json!({
                "error": self.to_string()
            })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use attestation_core::{
        Decision, MockTeeEvidence, MockTeeVerifier, MockTpmEvidence, Nonce, SubjectId, TcbStatus,
        TeeType,
    };
    use chrono::{Duration, Utc};
    use policy_engine::Policy;

    use super::*;

    fn policy() -> Policy {
        Policy::from_yaml(include_str!(
            "../../../configs/policies/require-mutual-attestation.yaml"
        ))
        .unwrap()
    }

    #[test]
    fn broker_verifies_tpm_evidence() {
        let broker = Broker::with_mock_backends(policy());
        let now = Utc::now();
        let binding = SessionBinding {
            nonce: Nonce("n".to_owned()),
            public_key_hash: "pkh".to_owned(),
            transcript_hash: None,
        };
        let evidence = Evidence::MockTpm(MockTpmEvidence {
            subject_id: SubjectId("a".to_owned()),
            ek_fingerprint: "ek".to_owned(),
            ak_fingerprint: "ak-good".to_owned(),
            pcr_selection: vec![10],
            pcr_values: BTreeMap::from([(10, "good-pcr-10".to_owned())]),
            measured_boot_ok: true,
            ima_runtime_ok: true,
            nonce: binding.nonce.clone(),
            public_key_hash: binding.public_key_hash.clone(),
            issued_at: now,
            expires_at: now + Duration::seconds(60),
            quote_signature_marker: "mock-tpm-quote-ok".to_owned(),
        });
        let result = broker.verify_evidence(&evidence, &binding).unwrap();
        assert_eq!(result.claims.final_decision, Decision::Allow);
    }

    #[test]
    fn broker_rejects_key_binding_mismatch() {
        let broker = Broker::with_mock_backends(policy());
        let now = Utc::now();
        let binding = SessionBinding {
            nonce: Nonce("n".to_owned()),
            public_key_hash: "pkh".to_owned(),
            transcript_hash: None,
        };
        let evidence = Evidence::MockTee(MockTeeEvidence {
            subject_id: SubjectId("b".to_owned()),
            tee_type: TeeType::MockSnp,
            measurement: "tee-good-measurement".to_owned(),
            tcb_status: TcbStatus::UpToDate,
            debug: false,
            instance_id: "tee-b".to_owned(),
            report_data: MockTeeVerifier::expected_report_data("n", "other"),
            nonce: binding.nonce.clone(),
            public_key_hash: "other".to_owned(),
            issued_at: now,
            expires_at: now + Duration::seconds(60),
        });
        let err = broker.verify_evidence(&evidence, &binding).unwrap_err();
        assert!(matches!(
            err,
            BrokerError::Attestation(AttestationError::PublicKeyBindingMismatch)
        ));
    }
}
