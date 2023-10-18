use ark_serialize::CanonicalSerialize;
use num_bigint::BigUint;
use serde::{Serialize, Deserialize};
use crate::evaluator::*;

pub const PERM_SIZE: usize = 64;
pub const DECK_SIZE: usize = 52;
pub const LOG_PERM_SIZE: usize = 6;
pub const NUM_SAMPLES: usize = 400;

/// EvalNetMsg represents the types of messages that
/// we expect to flow between the evaluator and networkd
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EvalNetMsg {
    ConnectionEstablished { success: bool },
    Greeting { message: String },
    PublishValue { 
        sender: String,
        handle: String,
        value: String
    },
    PublishBatchValue { 
        sender: String,
        handles: Vec<String>,
        values: Vec<String>
    },
    SendTriple { 
        sender: String, 
        receiver: String, 
        handle_a: String, 
        share_a: String,
        handle_b: String,
        share_b: String,
        handle_c: String,
        share_c: String,
    },
}

/// PermutationProof is a structure for the permutation proofs
pub struct PermutationProof {
    pub y1: F,
    pub y2: F,
    pub y3: F,
    pub y4: F,
    pub y5: F,
    pub pi_1: G1,
    pub pi_2: G1,
    pub pi_3: G1,
    pub pi_4: G1,
    pub pi_5: G1,
    pub f_com: G1,
    pub q_com: G1,
    pub t_com: G1,
}

/// EncryptProof is a structure for the encryptions and attached proofs
/// produced by encrypt_and_prove and verified by local_verify_encryption_proof
pub struct EncryptProof {
    pub pk: G2,
    pub ids: Vec<BigUint>,
    pub card_commitment: G1,
    pub masked_commitments: Vec<G1>,
    pub masked_evals: Vec<F>,
    pub eval_proofs: Vec<G1>,
    pub ciphertexts: Vec<(G2,Gt)>,
    pub sigma_proof: Option<SigmaProof>,
}

impl EncryptProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let mut pk_bytes = Vec::new();
        self.pk.serialize_uncompressed(&mut pk_bytes).unwrap();
        bytes.extend_from_slice(&pk_bytes);

        for id in &self.ids {
            bytes.extend_from_slice(&id.to_bytes_be());
        }

        let mut card_commitment_bytes = Vec::new();
        self.card_commitment.serialize_uncompressed(&mut card_commitment_bytes).unwrap();
        bytes.extend_from_slice(&card_commitment_bytes);

        for masked_commitment in &self.masked_commitments {
            let mut masked_commitment_bytes = Vec::new();
            masked_commitment.serialize_uncompressed(&mut masked_commitment_bytes).unwrap();
            bytes.extend_from_slice(&masked_commitment_bytes);
        }

        for masked_eval in &self.masked_evals {
            let mut masked_eval_bytes = Vec::new();
            masked_eval.serialize_uncompressed(&mut masked_eval_bytes).unwrap();
            bytes.extend_from_slice(&masked_eval_bytes);
        }

        for eval_proof in &self.eval_proofs {
            let mut eval_proof_bytes = Vec::new();
            eval_proof.serialize_uncompressed(&mut eval_proof_bytes).unwrap();
            bytes.extend_from_slice(&eval_proof_bytes);
        }

        for (ciphertext1, ciphertext2) in &self.ciphertexts {
            let mut ciphertext1_bytes = Vec::new();
            ciphertext1.serialize_uncompressed(&mut ciphertext1_bytes).unwrap();
            bytes.extend_from_slice(&ciphertext1_bytes);

            let mut ciphertext2_bytes = Vec::new();
            ciphertext2.serialize_uncompressed(&mut ciphertext2_bytes).unwrap();
            bytes.extend_from_slice(&ciphertext2_bytes);
        }

        bytes
    }
}

/// SigmaProof is a structure for the sigma protocol proof
pub struct SigmaProof {
    pub a1: G1,
    pub a2: G2,
    pub a3: Gt,
    pub x: F,
    pub y: F,
}