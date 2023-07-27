use ark_ff::Field;
use ark_std::{UniformRand, test_rng, ops::*};
use ark_serialize::{
    buffer_byte_size, CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Compress, EmptyFlags, Flags, SerializationError, Valid, Validate,
};

use std::collections::HashMap;
use std::hash::Hash;
use futures::{prelude::*, channel::*};

use sha2::{Sha256, Digest};
use bs58::*;

use crate::address_book::*;
use crate::common::*;
use crate::utils;
use crate::preprocessor::*;

pub enum Gate {
    BEAVER = 1, //denotes a beaver triple source gate that is output by pre-processing
    RAN = 2, // denotes a random gate that is the output of the pre-processing stage
    ADD = 3, // denotes an adder over 2 input wires
    MULT = 4, // denotes a multiplier over 2 input wires
    //OUTPUT = 5 // denotes an output gate that all parties observe in the clear
}


// outputs H(gate_type || gate_id) as a base-58 encoded string, 
// which is a handle we use to refer to gate output wires
// note to developer: ensure distinct gates have distinct gate_ids
// technically, we just need uniqueness amongst gates of the same type
fn compute_beaver_wire_ids(gate_id: u64) -> (String, String, String)
{
    let mut hasher_input = Vec::new();
    hasher_input.extend_from_slice(&(Gate::BEAVER as u64).to_be_bytes());
    hasher_input.extend_from_slice(&gate_id.to_be_bytes());
    hasher_input.extend_from_slice(&(1 as u64).to_be_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&hasher_input);
    let hash = hasher.finalize();
    let a = bs58::encode(hash).into_string();

    let mut hasher_input = Vec::new();
    hasher_input.extend_from_slice(&(Gate::BEAVER as u64).to_be_bytes());
    hasher_input.extend_from_slice(&gate_id.to_be_bytes());
    hasher_input.extend_from_slice(&(2 as u64).to_be_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&hasher_input);
    let hash = hasher.finalize();
    let b = bs58::encode(hash).into_string();

    let mut hasher_input = Vec::new();
    hasher_input.extend_from_slice(&(Gate::BEAVER as u64).to_be_bytes());
    hasher_input.extend_from_slice(&gate_id.to_be_bytes());
    hasher_input.extend_from_slice(&(3 as u64).to_be_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&hasher_input);
    let hash = hasher.finalize();
    let c = bs58::encode(hash).into_string();

    (a,b,c)
}

fn compute_ran_input_wire_id(gate_id: u64) -> String {

    //gate_type takes one of 4 possible gate types
    //gate_id denotes a unique identifier for this gate
    let mut hasher_input = Vec::new();
    hasher_input.extend_from_slice(&(Gate::RAN as u64).to_be_bytes());
    hasher_input.extend_from_slice(&gate_id.to_be_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&hasher_input);
    let hash = hasher.finalize();

    bs58::encode(hash).into_string()
}

fn compute_2_input_gate_output_wire_id(
    gate_type: Gate, x: &String, y: &String) -> String {
    let mut hasher_input = Vec::new();
    hasher_input.extend_from_slice(&(gate_type as u64).to_be_bytes());
    hasher_input.extend_from_slice(x.as_bytes());
    hasher_input.extend_from_slice(y.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&hasher_input);
    let hash = hasher.finalize();

    bs58::encode(hash).into_string()
}

type F = ark_bls12_377::Fr;

macro_rules! send_over_network {
    ($msg:expr, $tx:expr) => {
        let r = $tx.send($msg).await;
        if let Err(err) = r {
            eprint!("evaluator error {:?}", err);
        }
    };
}

pub struct Evaluator {
    /// local peer id
    id: Pok3rPeerId,
    /// information about all other peers
    addr_book: Pok3rAddrBook,
    /// sender channel towards the networkd
    tx: mpsc::UnboundedSender<EvalNetMsg>,
    /// receiver channel from the networkd
    rx: mpsc::UnboundedReceiver<EvalNetMsg>,
    /// stores the share associated with each wire
    wire_shares: HashMap<String, F>,
    /// stires the partially opened values
    openings: HashMap<String, HashMap<String, F>>
}

impl Evaluator {
    pub async fn new(
        id: &Pok3rPeerId,
        addr_book: Pok3rAddrBook,
        tx: mpsc::UnboundedSender<EvalNetMsg>, 
        mut rx: mpsc::UnboundedReceiver<EvalNetMsg>
    ) -> Self {
        // we expect the first message from the 
        // networkd to be a connection established;
        // so, here we will loop till we get that
        loop {
            //do a blocking recv on the rx channel
            let msg: EvalNetMsg = rx.select_next_some().await;
            match msg {
                EvalNetMsg::ConnectionEstablished { success } => {
                    if success {
                        println!("evaluator connected to the network");
                        break;
                    }
                },
                _ => continue,
            }
        }

        Evaluator { 
            id: id.clone(), 
            addr_book, 
            tx, 
            rx,
            wire_shares: HashMap::new(),
            openings: HashMap::new()
        }
    }

    pub async fn test_networking(&mut self) {
        let greeting = EvalNetMsg::Greeting { message: format!("Hello from {}", self.id) };
        send_over_network!(greeting, self.tx);

        //we expect greetings from all other players
        let num_other_parties = self.addr_book.len() - 1;
        for _ in 0..num_other_parties {
            let msg: EvalNetMsg = self.rx.select_next_some().await;
            match msg {
                EvalNetMsg::Greeting { message } => { println!("evaluator received: {:?}", message); },
                _ => continue,
            }
        }
    }

    /// asks the pre-processor to generate an additive sharing of a random value
    /// returns a string handle, which can be used to access the share in future
    pub fn ran(&mut self, gate_id: u64) -> String {
        let r = F::rand(&mut rand::thread_rng());

        let handle = compute_ran_input_wire_id(gate_id);
        self.wire_shares.insert(handle.clone(), r);
        handle
    }

    pub fn add(&mut self, 
        handle_x: &String, 
        handle_y: &String) -> String {
        let handle = compute_2_input_gate_output_wire_id(
            Gate::ADD, handle_x, handle_y);
        let x = self.wire_shares.get(handle_x).unwrap();
        let y = self.wire_shares.get(handle_y).unwrap();
        let sum: F = x + y;
        self.wire_shares.insert(handle.clone(), sum);
        handle
    }

    /// TODO: HACK ALERT! make this a little more secure please!
    pub async fn beaver(&mut self, gate_id: u64) -> (String, String, String) {
        let (handle_a, handle_b, handle_c) = compute_beaver_wire_ids(gate_id);

        //only one party will be responsible for generating this
        let n: usize = self.addr_book.len();
        let designated_generator = gate_id % (n as u64);
        let my_id = get_node_id_via_peer_id(&self.addr_book, &self.id).unwrap();

        // I am designated generator
        if my_id == designated_generator {
            //generate random a, b, c
            let a = F::rand(&mut rand::thread_rng());
            let b = F::rand(&mut rand::thread_rng());
            let c = a * b;
            assert_eq!(c, a * b);

            let shares_a = utils::compute_additive_shares(&a, n);
            let shares_b = utils::compute_additive_shares(&b, n);
            let shares_c = utils::compute_additive_shares(&c, n);
            
            //deal shares of a, b, c for all parties
            for peer_id in self.addr_book.keys() {

                let node_id = get_node_id_via_peer_id(
                    &self.addr_book, 
                    &peer_id
                ).unwrap() as usize;

                let a_i = shares_a.get(node_id).unwrap();
                let b_i = shares_b.get(node_id).unwrap();
                let c_i = shares_c.get(node_id).unwrap();

                // distribute shares to all other parties
                if ! self.id.eq(peer_id) {
                    let msg = EvalNetMsg::SendTriple {
                        sender: self.id.clone(),
                        receiver: peer_id.clone(),
                        handle_a: handle_a.clone(),
                        share_a: bs58::encode(utils::field_to_bytes(&a_i)).into_string(),
                        handle_b: handle_b.clone(),
                        share_b: bs58::encode(utils::field_to_bytes(&b_i)).into_string(),
                        handle_c: handle_c.clone(),
                        share_c: bs58::encode(utils::field_to_bytes(&c_i)).into_string(),
                    };
                    send_over_network!(msg, self.tx);
                } else { // self.id.eq(peer_id)
                    self.wire_shares.insert(handle_a.clone(), *a_i);
                    self.wire_shares.insert(handle_b.clone(), *b_i);
                    self.wire_shares.insert(handle_c.clone(), *c_i);
                }
            }
        } else { // I am not designated, so just receive shares
            loop {
                if self.exists_in_wire_shares(
                    vec![
                        handle_a.clone(), 
                        handle_b.clone(), 
                        handle_c.clone()
                        ]) {
                    break;
                }
                
                let msg: EvalNetMsg = self.rx.select_next_some().await;
                self.process_next_message(&msg);
            }
        }

        return (handle_a, handle_b, handle_c)
    }

    pub async fn output_wire(&mut self, wire_handle: &String) -> F {
        let my_share: F = self.wire_shares.get(wire_handle).unwrap().clone();

        let msg = EvalNetMsg::PublishShare {
            sender: self.id.clone(),
            handle: wire_handle.clone(),
            share: bs58::encode(utils::field_to_bytes(&my_share)).into_string(),
        };
        send_over_network!(msg, self.tx);

        let mut sum: F = my_share;
        let peers: Vec<Pok3rPeerId> = self.addr_book.keys().cloned().collect();
        
        for peer_id in peers {
            if self.id.eq(&peer_id) { continue; }

            loop {
                if self.openings.contains_key(wire_handle) {
                    let sender_exists_for_handle = self.openings
                        .get(wire_handle)
                        .unwrap()
                        .contains_key(&peer_id);
                    if sender_exists_for_handle { break; } //we already have it!
                }

                let msg: EvalNetMsg = self.rx.select_next_some().await;
                self.process_next_message(&msg);
            }

            sum += self.openings
                .get(wire_handle)
                .unwrap()
                .get(&peer_id)
                .unwrap();
        }
        sum
    }

    //returns the handle which 
    fn process_next_message(&mut self, msg: &EvalNetMsg) {
        match msg {
            EvalNetMsg::SendTriple { 
                sender,
                receiver,
                handle_a,
                share_a,
                handle_b,
                share_b,
                handle_c, 
                share_c 
            } => {
                // if wrong receiver, then ignore -- TODO: remove after encryption
                let match_on_receiver = receiver.eq(&self.id);
                if ! match_on_receiver { return; }

                // if already exists, then ignore
                if self.exists_in_wire_shares(
                    vec![
                        handle_a.clone(), 
                        handle_b.clone(), 
                        handle_c.clone()
                        ]) {
                    return;
                }

                // insert the received values
                let a_i = utils::bytes_to_field(&bs58::decode(share_a).into_vec().unwrap());
                let b_i = utils::bytes_to_field(&bs58::decode(share_b).into_vec().unwrap());
                let c_i = utils::bytes_to_field(&bs58::decode(share_c).into_vec().unwrap());
                // store what we received
                self.wire_shares.insert(handle_a.clone(), a_i);
                self.wire_shares.insert(handle_b.clone(), b_i);
                self.wire_shares.insert(handle_c.clone(), c_i);
            },
            EvalNetMsg::PublishShare { 
                sender,
                handle,
                share
            } => {
                // if already exists, then ignore
                if self.openings.contains_key(handle) {
                    let sender_exists_for_handle = self.openings
                        .get(handle)
                        .unwrap()
                        .contains_key(sender);
                    if sender_exists_for_handle { return; } //ignore, duplicate!
                } else {
                    self.openings.insert(handle.clone(), HashMap::new());
                }

                let s = utils::bytes_to_field(&bs58::decode(share).into_vec().unwrap());
                self.openings
                    .get_mut(handle)
                    .unwrap()
                    .insert(sender.clone(), s);
            },
            _ => return,
        }
    }

    fn exists_in_wire_shares(&self, handles: Vec<String>) -> bool {
        handles
            .iter()
            .map(|h| self.wire_shares.contains_key(h))
            .collect::<Vec<bool>>()
            .iter()
            .all(|&b| b)
    }

}

