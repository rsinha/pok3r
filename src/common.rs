use serde::{Serialize, Deserialize};

/// Used by networkd to indicate to the evaluator
/// that connection is established with all parties
struct ConnectionEstablished { }

/// Test: used for exchanging friendly hellos
#[derive(Serialize, Deserialize)]
struct Greeting {
    message: String
}

/// Used to reconstruct values collaboratively
#[derive(Serialize, Deserialize)]
struct PublishShare {
    sender: String, //peer id of the party generating the message
    value: String //base58 encoding the byte array representing field element
}

/// Used to transmit values with other parties
#[derive(Serialize, Deserialize)]
struct SendShare {
    sender: String, //peer id of the party generating the message
    value: String //base58 encoding the byte array representing field element
}

/// EvalNetMsg represents the types of messages that
/// we expect to flow between the evaluator and networkd
enum EvalNetMsg {
    ConnectionEstablished(ConnectionEstablished),
    Greeting(Greeting),
    PublishShare(PublishShare),
    SendShare(SendShare),
}