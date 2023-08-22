use serde::{Serialize, Deserialize};
use crate::evaluator::*;

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

/// EncryptProof is a structure for the encryptions and attached proofs
/// produced by encrypt_and_prove and verified by local_verify_encryption_proof
pub struct EncryptProof<'a> {
    pub pk: G2,
    pub ids: Vec<&'a [u8]>,
    pub card_commitment: G1,
    pub masked_commitments: Vec<G1>,
    pub masked_evals: Vec<F>,
    pub eval_proofs: Vec<G1>,
    pub ciphertexts: Vec<(G1,Gt)>,
    pub sigma_proof: SigmaProof,
}

/// SigmaProof is a structure for the sigma protocol proof
pub struct SigmaProof {
    pub a1: G1,
    pub a2: G1,
    pub a3: Gt,
    pub a4: Gt,
    pub x: F,
    pub y: F,
}