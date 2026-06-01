use crate::{
    AttestationError, AttestationResult, Evidence, EvidenceType, SessionBinding, VerifierId,
};

pub trait EvidenceVerifier: Send + Sync {
    fn verifier_id(&self) -> VerifierId;
    fn evidence_type(&self) -> EvidenceType;
    fn verify(
        &self,
        evidence: &Evidence,
        expected: &SessionBinding,
    ) -> Result<AttestationResult, AttestationError>;
}
