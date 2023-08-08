use serde::{Serialize, Deserialize};

/// EvalNetMsg represents the types of messages that
/// we expect to flow between the evaluator and networkd
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EvalNetMsg {
    ConnectionEstablished { success: bool },
    Greeting { message: String },
    PublishShare { 
        sender: String,
        handle: String,
        share: String 
    },
    PublishShareInExponent { 
        sender: String,
        handle: String,
        share: String
    },
    PublishCommitment { 
        sender: String,
        handle: String,
        commitment: String
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