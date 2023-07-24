use serde::{Serialize, Deserialize};

/// Used by networkd to indicate to the evaluator
/// that connection is established with all parties
#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionEstablished { }

/// Test: used for exchanging friendly hellos
#[derive(Debug, Serialize, Deserialize)]
pub struct Greeting {
    pub message: String
}

/// Used to reconstruct values collaboratively
#[derive(Debug, Serialize, Deserialize)]
pub struct PublishShare {
    sender: String, //peer id of the party generating the message
    value: String //base58 encoding the byte array representing field element
}

/// Used to transmit values with other parties
#[derive(Debug, Serialize, Deserialize)]
pub struct SendShare {
    sender: String, //peer id of the party generating the message
    value: String //base58 encoding the byte array representing field element
}

/// EvalNetMsg represents the types of messages that
/// we expect to flow between the evaluator and networkd
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EvalNetMsg {
    ConnectionEstablished(ConnectionEstablished),
    Greeting(Greeting),
    PublishShare(PublishShare),
    SendShare(SendShare),
}