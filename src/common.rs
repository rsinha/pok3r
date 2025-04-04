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

pub struct EncryptProof {
    pub pk: G2,
    pub ids: Vec<BigUint>,
    pub card_commitment: G1,
    pub card_poly_eval: F,
    pub eval_proof: G1,
    pub ciphertexts: (G2,Vec<Gt>),
    pub hiding_ciphertext: Gt,
    pub t: Gt,
    pub sigma_proof: Option<SigmaProof>,
}

pub struct SigmaProof {
    pub a1: G2,
    pub a2: Gt,
    pub eta: F,
    pub y: F,
}