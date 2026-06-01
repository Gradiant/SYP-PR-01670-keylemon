use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SubjectId(pub String);

impl From<&str> for SubjectId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VerifierId(pub String);

impl From<&str> for VerifierId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Nonce(pub String);

impl From<&str> for Nonce {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    MockTpm,
    MockTee,
    NoHardware,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityType {
    None,
    PhysicalTpm,
    Vtpm,
    Tee,
    TeeBackedVtpm,
    PhysicalTpmTee,
    Extension,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustAnchor {
    EkCert,
    IakIdevid,
    TeeVendorChain,
    CspAssertion,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    Degraded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositeAttestationLevel {
    None,
    Software,
    CspAsserted,
    TeeBacked,
    HardwareTpm,
    Composed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TpmType {
    Physical,
    Virtual,
    Emulated,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeeType {
    MockTdx,
    MockSnp,
    MockSgx,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcbStatus {
    UpToDate,
    Acceptable,
    OutOfDate,
    Revoked,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionBinding {
    pub nonce: Nonce,
    pub public_key_hash: String,
    pub transcript_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationCapability {
    pub capability_type: CapabilityType,
    pub evidence_types: Vec<EvidenceType>,
    pub trust_anchor: TrustAnchor,
    pub verifier_id: VerifierId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MockTpmEvidence {
    pub subject_id: SubjectId,
    pub ek_fingerprint: String,
    pub ak_fingerprint: String,
    pub pcr_selection: Vec<u32>,
    pub pcr_values: BTreeMap<u32, String>,
    pub measured_boot_ok: bool,
    pub ima_runtime_ok: bool,
    pub nonce: Nonce,
    pub public_key_hash: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub quote_signature_marker: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MockTeeEvidence {
    pub subject_id: SubjectId,
    pub tee_type: TeeType,
    pub measurement: String,
    pub tcb_status: TcbStatus,
    pub debug: bool,
    pub instance_id: String,
    pub report_data: String,
    pub nonce: Nonce,
    pub public_key_hash: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoHardwareEvidence {
    pub subject_id: SubjectId,
    pub nonce: Nonce,
    pub public_key_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    MockTpm(MockTpmEvidence),
    MockTee(MockTeeEvidence),
    NoHardware(NoHardwareEvidence),
}

impl Evidence {
    pub fn evidence_type(&self) -> EvidenceType {
        match self {
            Self::MockTpm(_) => EvidenceType::MockTpm,
            Self::MockTee(_) => EvidenceType::MockTee,
            Self::NoHardware(_) => EvidenceType::NoHardware,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmClaims {
    pub tpm_present: bool,
    pub tpm_type: TpmType,
    pub ek_fingerprint: String,
    pub ak_fingerprint: String,
    pub ek_cert_status: String,
    pub pcr_policy_ok: bool,
    pub pcr_selection: Vec<u32>,
    pub measured_boot_ok: bool,
    pub ima_runtime_ok: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeClaims {
    pub tee_present: bool,
    pub tee_type: TeeType,
    pub measurement: String,
    pub tcb_status: TcbStatus,
    pub debug_disabled: bool,
    pub instance_id: String,
    pub report_data_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedClaims {
    pub subject_id: SubjectId,
    pub capabilities: Vec<CapabilityType>,
    pub evidence_type: EvidenceType,
    pub verifier_id: VerifierId,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub freshness_nonce: Nonce,
    pub public_key_hash: String,
    pub transcript_hash: Option<String>,
    pub tpm: Option<TpmClaims>,
    pub tee: Option<TeeClaims>,
    pub composite_attestation_level: CompositeAttestationLevel,
    pub final_decision: Decision,
    pub raw_summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationResult {
    pub claims: NormalizedClaims,
    pub failure_reason: Option<String>,
}

impl AttestationResult {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.claims.expires_at <= now
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub reason: String,
}

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("unsupported evidence type")]
    UnsupportedEvidence,
    #[error("evidence expired")]
    Expired,
    #[error("nonce mismatch")]
    NonceMismatch,
    #[error("public key binding mismatch")]
    PublicKeyBindingMismatch,
    #[error("unknown attestation key")]
    UnknownAk,
    #[error("bad pcr value for index {0}")]
    BadPcr(u32),
    #[error("measured boot policy failed")]
    MeasuredBootFailed,
    #[error("ima runtime policy failed")]
    ImaFailed,
    #[error("invalid quote marker")]
    InvalidQuoteMarker,
    #[error("tee debug mode enabled")]
    TeeDebugEnabled,
    #[error("tee measurement denied")]
    TeeMeasurementDenied,
    #[error("tee type denied")]
    TeeTypeDenied,
    #[error("tee tcb status denied")]
    TeeTcbDenied,
    #[error("tee report data binding mismatch")]
    TeeReportDataMismatch,
    #[error("{0}")]
    Other(String),
}
