use std::{fmt, collections::HashMap};

pub struct Pok3rPeer {
    // base58 encoding of ed25519 pub key
    pub peer_id: Pok3rPeerId,
    // unique index between 1 and size of addr book (not used in SPDZ)
    pub node_id: u64,
}

impl fmt::Display for Pok3rPeer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({}, {})", self.node_id, self.peer_id)
    }
}

pub type Pok3rPeerId = String;

pub type Pok3rAddrBook = HashMap<Pok3rPeerId, Pok3rPeer>;