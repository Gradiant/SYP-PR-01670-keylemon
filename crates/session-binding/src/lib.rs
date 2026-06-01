use attestation_core::{AttestationResult, Nonce};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub struct EphemeralKeypair {
    signing_key: SigningKey,
}

impl EphemeralKeypair {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn public_key_hash(&self) -> String {
        public_key_hash(&self.public_key_bytes())
    }
}

pub fn generate_nonce() -> Nonce {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    Nonce(hex::encode(bytes))
}

pub fn public_key_hash(public_key: &[u8]) -> String {
    hex::encode(Sha256::digest(public_key))
}

pub fn transcript_hash(parts: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part);
    }
    hex::encode(digest.finalize())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedAttestationToken {
    pub result: AttestationResult,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub public_key_hash: String,
    pub signature: String,
}

#[derive(Clone)]
pub struct TokenIssuer {
    signing_key: SigningKey,
}

impl TokenIssuer {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn issue(
        &self,
        result: AttestationResult,
        public_key_hash: String,
        lifetime: Duration,
    ) -> Result<SignedAttestationToken, TokenError> {
        if result.claims.public_key_hash != public_key_hash {
            return Err(TokenError::PublicKeyBindingMismatch);
        }
        let issued_at = Utc::now();
        let expires_at = issued_at + lifetime;
        let payload = token_payload(&result, issued_at, expires_at, &public_key_hash)?;
        let signature = self.signing_key.sign(&payload);
        Ok(SignedAttestationToken {
            result,
            issued_at,
            expires_at,
            public_key_hash,
            signature: STANDARD.encode(signature.to_bytes()),
        })
    }
}

pub struct TokenVerifier {
    verifying_key: VerifyingKey,
}

impl TokenVerifier {
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
    }

    pub fn verify(
        &self,
        token: &SignedAttestationToken,
        expected_public_key_hash: &str,
    ) -> Result<(), TokenError> {
        if token.expires_at <= Utc::now() {
            return Err(TokenError::Expired);
        }
        if token.public_key_hash != expected_public_key_hash {
            return Err(TokenError::PublicKeyBindingMismatch);
        }
        let payload = token_payload(
            &token.result,
            token.issued_at,
            token.expires_at,
            &token.public_key_hash,
        )?;
        let signature_bytes = STANDARD
            .decode(&token.signature)
            .map_err(|_| TokenError::BadSignature)?;
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| TokenError::BadSignature)?;
        self.verifying_key
            .verify(&payload, &signature)
            .map_err(|_| TokenError::BadSignature)
    }
}

fn token_payload(
    result: &AttestationResult,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    public_key_hash: &str,
) -> Result<Vec<u8>, TokenError> {
    #[derive(Serialize)]
    struct Payload<'a> {
        result: &'a AttestationResult,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        public_key_hash: &'a str,
    }
    Ok(serde_json::to_vec(&Payload {
        result,
        issued_at,
        expires_at,
        public_key_hash,
    })?)
}

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("token expired")]
    Expired,
    #[error("token public-key binding mismatch")]
    PublicKeyBindingMismatch,
    #[error("bad token signature")]
    BadSignature,
    #[error("token serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use attestation_core::{
        CapabilityType, CompositeAttestationLevel, Decision, EvidenceType, NormalizedClaims,
        SubjectId, VerifierId,
    };

    use super::*;

    fn result(public_key_hash: String) -> AttestationResult {
        let now = Utc::now();
        AttestationResult {
            claims: NormalizedClaims {
                subject_id: SubjectId("subject".to_owned()),
                capabilities: vec![CapabilityType::Tee],
                evidence_type: EvidenceType::MockTee,
                verifier_id: VerifierId("test".to_owned()),
                issued_at: now,
                expires_at: now + Duration::seconds(60),
                freshness_nonce: Nonce("n".to_owned()),
                public_key_hash,
                transcript_hash: None,
                tpm: None,
                tee: None,
                composite_attestation_level: CompositeAttestationLevel::TeeBacked,
                final_decision: Decision::Allow,
                raw_summary: "test".to_owned(),
            },
            failure_reason: None,
        }
    }

    #[test]
    fn token_verifies_with_matching_key_hash() {
        let key = EphemeralKeypair::generate();
        let issuer = TokenIssuer::generate();
        let token = issuer
            .issue(
                result(key.public_key_hash()),
                key.public_key_hash(),
                Duration::seconds(60),
            )
            .unwrap();
        TokenVerifier::new(issuer.verifying_key())
            .verify(&token, &key.public_key_hash())
            .unwrap();
    }
}
