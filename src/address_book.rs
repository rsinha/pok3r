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

pub fn get_node_id_via_peer_id(
    addr_book: &Pok3rAddrBook, 
    peer_id: &Pok3rPeerId) -> Option<u64> {
    match addr_book.get(peer_id) {
        Some(p) => Some(p.node_id),
        None => None
    }
}

pub fn get_peer_id_via_node_id(addr_book: &Pok3rAddrBook, node_id: u64) -> Option<Pok3rPeerId> {
    for (id, peer) in addr_book.iter() {
        if peer.node_id == node_id {
            return Some(id.clone());
        }
    }
    return None;
}