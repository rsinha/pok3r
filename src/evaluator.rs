
use ark_ec::{Group, pairing::*};
use ark_poly::DenseUVPolynomial;
use ark_poly::univariate::DenseOrSparsePolynomial;
use ark_poly::univariate::DensePolynomial;
use ark_std::UniformRand;
use ark_ff::{Field, /* FftField */ };
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_ec::{pairing::Pairing, CurveGroup, AffineRepr};
use ark_std::{Zero, One};
use std::collections::HashMap;
use std::ops::*;
use futures::{prelude::*, channel::*};
use ark_std::io::Cursor;
//use rand::{rngs::StdRng, SeedableRng};
use sha2::{Sha256, Digest};
use num_bigint::BigUint;

use crate::address_book::*;
use crate::common::*;
use crate::utils;

pub type Curve = ark_bls12_377::Bls12_377;
//type KZG = KZG10::<Curve, DensePolynomial<<Curve as Pairing>::ScalarField>>;
pub type F = ark_bls12_377::Fr;
pub type G1 = <Curve as Pairing>::G1Affine;
pub type G2 = <Curve as Pairing>::G2Affine;
pub type Gt = PairingOutput<Curve>;

pub enum Gate {
    BEAVER = 1, // denotes a beaver triple source gate that is output by pre-processing
    RAN = 2, // denotes a random gate that is the output of the pre-processing stage
    ADD = 3, // denotes an adder over 2 input wires
    MULT = 4, // denotes a multiplier over 2 input wires
    INV = 5, // denotes an inversion gate
    EXP = 6, // denotes an exponentiation (by 64) gate
    SCALE = 7, // denotes a scaling gate
    CLEARADD = 8, // denotes a addition gate for one input in clear and another shared
    FIXED = 9, // denotes a fixed value that is shared
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

fn compute_fixed_wire_id(value: F) -> String {
    let mut hasher_input = Vec::new();
    hasher_input.extend_from_slice(&(Gate::FIXED as u64).to_be_bytes());

    let mut value_bytes = Vec::new();
    value.serialize_uncompressed(&mut value_bytes).unwrap();
    hasher_input.extend_from_slice(&value_bytes);

    let mut hasher = Sha256::new();
    hasher.update(&hasher_input);
    let hash = hasher.finalize();

    bs58::encode(hash).into_string()
}

fn compute_scale_wire_id(gate_id: u64) -> String {
    let mut hasher_input = Vec::new();
    hasher_input.extend_from_slice(&(Gate::SCALE as u64).to_be_bytes());
    hasher_input.extend_from_slice(&gate_id.to_be_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&hasher_input);
    let hash = hasher.finalize();

    bs58::encode(hash).into_string()
}

fn compute_clear_add_wire_id(gate_id: u64) -> String {
    let mut hasher_input = Vec::new();
    hasher_input.extend_from_slice(&(Gate::CLEARADD as u64).to_be_bytes());
    hasher_input.extend_from_slice(&gate_id.to_be_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&hasher_input);
    let hash = hasher.finalize();

    bs58::encode(hash).into_string()
}

fn compute_inversion_wire_id(x: &String) -> String {
    let mut hasher_input = Vec::new();
    hasher_input.extend_from_slice(&(Gate::INV as u64).to_be_bytes());
    hasher_input.extend_from_slice(x.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&hasher_input);
    let hash = hasher.finalize();

    bs58::encode(hash).into_string()
}

fn compute_exp_wire_id(x: &String) -> String {
    let mut hasher_input = Vec::new();
    hasher_input.extend_from_slice(&(Gate::EXP as u64).to_be_bytes());
    hasher_input.extend_from_slice(x.as_bytes());

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


macro_rules! send_over_network {
    ($msg:expr, $tx:expr) => {
        let r = $tx.send($msg).await;
        if let Err(err) = r {
            eprint!("evaluator error {:?}", err);
        }
    };
}

pub struct GateCount {
    num_beaver: u64,
    num_ran: u64,
    num_scale: u64,
    num_clear_add: u64
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
    /// stores incoming messages indexed by identifier and then by peer id
    mailbox: HashMap<String, HashMap<String, String>>,
    /// keep track of gates
    gate_counters: GateCount
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
            mailbox: HashMap::new(),
            gate_counters: GateCount { num_beaver: 0, num_ran: 0, num_scale: 0, num_clear_add: 0 }
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
    pub fn ran(&mut self) -> String {
        let gate_id = self.gate_counters.num_ran;
        self.gate_counters.num_ran += 1;

        let r = F::rand(&mut rand::thread_rng());

        let handle = compute_ran_input_wire_id(gate_id);
        self.wire_shares.insert(handle.clone(), r);
        handle
    }

    /// returns shares of a random element in {1, ω, ..., ω^63}
    pub async fn ran_64(&mut self, h_a: &String) -> String {
        // we will cheat a bit and use the same gate type
        let gate_id = self.gate_counters.num_ran;
        self.gate_counters.num_ran += 1;
        let h_c = compute_ran_input_wire_id(gate_id);

        let h_a_exp_64 = self.exp(h_a).await;
        let a_exp_64 = self.output_wire(&h_a_exp_64).await;
    
        if a_exp_64 == F::from(0) {
            panic!("Highly improbable event occurred. Abort!");
        }
    
        let mut l = a_exp_64;
        for _ in 0..6 {
            l = utils::compute_root(&l);
        }

        let share_c = self.get_wire(h_a) / l;
        self.wire_shares.insert(h_c.clone(), share_c);
        h_c
    }

    /// outputs the wire label denoting the [x] + [y]
    pub fn add(&mut self, 
        handle_x: &String, 
        handle_y: &String) -> String {
        let handle = compute_2_input_gate_output_wire_id(
            Gate::ADD, handle_x, handle_y);

        let share_x = self.get_wire(handle_x);
        let share_y = self.get_wire(handle_y);

        self.wire_shares.insert(handle.clone(), share_x + share_y);
        handle
    }
    
    pub async fn inv(&mut self, 
        handle_in: &String,
        handle_r: &String,
        beaver_handles: (&String, &String, &String)
    ) -> String {
        // goal: compute inv([s])
        // step 1: invoke ran_p to obtain [r]
        // step 2: invoke mult to get [q] = [r . s]
        // step 3: reconstruct q = r . s
        // step 4: return [r] / q
        
        let handle_out = compute_inversion_wire_id(handle_in);
        
        let handle_r_mult_s = self.mult(
            handle_in, 
            handle_r, 
            beaver_handles).await;
        //reconstruct the padded wires in the clear
        let r_mult_s = self.output_wire(&handle_r_mult_s).await;

        let q_inv = F::from(1) / r_mult_s;
        let wire_out = q_inv * self.get_wire(handle_r);

        self.wire_shares.insert(handle_out.clone(), wire_out);

        handle_out
    }

    // Adds [x] to y in the clear and outputs handle to the resulting share
    pub fn clear_add(&mut self,
        handle_x: &String,
        y: F
    ) -> String {
        let gate_id = self.gate_counters.num_clear_add;
        self.gate_counters.num_clear_add += 1;

        let handle_out = compute_clear_add_wire_id(gate_id);

        let x = self.get_wire(&handle_x);

        let my_id = get_node_id_via_peer_id(&self.addr_book, &self.id).unwrap();
        let clear_add_share: F = match my_id {
            0 => {x + y}
            _ => {x}
        };

        self.wire_shares.insert(handle_out.clone(), clear_add_share);

        handle_out
    }

    // Scales [x] by scalar and outputs handle to the resulting share
    pub fn scale(&mut self, 
        handle_in: &String, 
        scalar: F
    ) -> String {
        let gate_id = self.gate_counters.num_scale;
        self.gate_counters.num_scale += 1;

        let handle_out = compute_scale_wire_id(gate_id);

        let x = self.get_wire(handle_in);

        self.wire_shares.insert(handle_out.clone(), x * scalar);

        handle_out
    }

    /// given: triple ([a], [b], [c]) and inputs ([x], [y])
    /// reveals: x + a, y + b
    /// computes [x.y] = (x+a).(y+b) - (x+a).[b] - (y+b).[a] + [c]
    /// outputs the wire label denoting [x.y]
    pub async fn mult(&mut self, 
        handle_x: &String, 
        handle_y: &String,
        beaver_handles: (&String, &String, &String)
    ) -> String {
        //desugar the beaver triple handles
        let (handle_a, handle_b, handle_c) = beaver_handles;
        let share_a = self.get_wire(handle_a);
        let share_b = self.get_wire(handle_b);
        let share_c = self.get_wire(handle_c);

        // our strategy would be to re-use other components
        //construct adder gates for the padded wires
        let handle_x_plus_a = self.add(handle_x, handle_a);
        let handle_y_plus_b = self.add(handle_y, handle_b);

        //reconstruct the padded wires in the clear
        let x_plus_a = self.output_wire(&handle_x_plus_a).await;
        let y_plus_b = self.output_wire(&handle_y_plus_b).await;

        let handle = compute_2_input_gate_output_wire_id(
            Gate::MULT, handle_x, handle_y);
        
        //only one party should add the constant term
        let my_id = get_node_id_via_peer_id(&self.addr_book, &self.id).unwrap();
        let share_x_mul_y: F = match my_id {
            0 => {
                x_plus_a * y_plus_b 
                - x_plus_a * share_b 
                - y_plus_b * share_a 
                + share_c
            },
            _ => {
                F::from(0)
                - x_plus_a * share_b 
                - y_plus_b * share_a 
                + share_c
            }
        };
        self.wire_shares.insert(handle.clone(), share_x_mul_y);
        handle
    }

    pub async fn fixed_wire_handle(&mut self, value: F) -> String {
        let handle = compute_fixed_wire_id(value);
        
        let my_id = get_node_id_via_peer_id(&self.addr_book, &self.id).unwrap();
        let share: F = match my_id {
            0 => value,
            _ => F::from(0)
        };

        self.wire_shares.insert(handle.clone(), share);
        handle
    }

    /// PolyEval takes as input a shared polynomial f(x) and a point x and returns share of f(x)
    pub async fn share_poly_eval(&mut self, 
        f_poly_share: DensePolynomial<F>,
        x: F,
     ) -> String {

        // Hijacking the scale gate to compute f(x)
        let gate_id = self.gate_counters.num_scale;
        self.gate_counters.num_scale += 1;

        let handle_out = compute_scale_wire_id(gate_id);


        let mut sum = F::zero();
        let mut x_pow = F::one();
        for coeff in f_poly_share.coeffs.iter() {
            sum += coeff * &x_pow;
            x_pow *= x;
        }

        self.wire_shares.insert(handle_out.clone(), sum);
        handle_out

    }

    /// TODO: HACK ALERT! make this a little more secure please!
    pub async fn beaver(&mut self) -> (String, String, String) {
        let gate_id = self.gate_counters.num_beaver;
        self.gate_counters.num_beaver += 1;

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
                        share_a: encode_f_as_bs58_str(&a_i),
                        handle_b: handle_b.clone(),
                        share_b: encode_f_as_bs58_str(&b_i),
                        handle_c: handle_c.clone(),
                        share_c: encode_f_as_bs58_str(&c_i),
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
        let my_share = self.get_wire(wire_handle);

        let msg = EvalNetMsg::PublishValue {
            sender: self.id.clone(),
            handle: wire_handle.clone(),
            value: encode_f_as_bs58_str(&my_share),
        };
        send_over_network!(msg, self.tx);

        let incoming_msgs = self.collect_messages_from_all_peers(wire_handle).await;
        let incoming_values: Vec<F> = incoming_msgs
            .into_iter()
            .map(|x| decode_bs58_str_as_f(&x))
            .collect();

        let mut sum: F = my_share;
        for v in incoming_values { sum += v; }
        sum
    }

    // //on input wire [x], this outputs g^[x], and reconstructs and outputs g^x
    // we will use G1
    pub async fn output_wire_in_exponent(&mut self, wire_handle: &String) -> G1 {
        let my_share = self.get_wire(wire_handle);
        let g = <Curve as Pairing>::G1Affine::generator();
        let my_share_exp = g.clone().mul(my_share).into_affine();
        
        self.add_g1_elements_from_all_parties(
            &my_share_exp, 
            wire_handle
        ).await
    }

    // //on input wire [x], this outputs g^[x], and reconstructs and outputs g^x
    pub async fn add_g1_elements_from_all_parties(
        &mut self, value: &G1, 
        identifier: &String
    ) -> G1 {

        let msg = EvalNetMsg::PublishValue {
            sender: self.id.clone(),
            handle: identifier.clone(),
            value: encode_g1_as_bs58_str(value),
        };
        send_over_network!(msg, self.tx);

        let incoming_msgs = self.collect_messages_from_all_peers(identifier).await;

        let incoming_values: Vec<G1> = incoming_msgs
            .into_iter()
            .map(|x| decode_bs58_str_as_g1(&x))
            .collect();

        let mut sum: G1 = value.clone();
        for v in incoming_values { sum = sum.add(v).into_affine(); }
        sum
    }

    // //on input wire [x], this outputs g^[x], and reconstructs and outputs g^x
    pub async fn add_gt_elements_from_all_parties(
        &mut self, value: &Gt, 
        identifier: &String
    ) -> Gt {

        let msg = EvalNetMsg::PublishValue {
            sender: self.id.clone(),
            handle: identifier.clone(),
            value: encode_gt_as_bs58_str(value),
        };
        send_over_network!(msg, self.tx);

        let incoming_msgs = self.collect_messages_from_all_peers(identifier).await;

        let incoming_values: Vec<Gt> = incoming_msgs
            .into_iter()
            .map(|x| decode_bs58_str_as_gt(&x))
            .collect();

        let mut sum: Gt = value.clone();
        for v in incoming_values { sum = sum.add(v); }
        sum
    }

    // secret-shared MSM, where scalars are secret shares. Outputs MSM in the clear.
    pub async fn exp_and_reveal_gt(
        &mut self, 
        bases: Vec<Gt>, 
        exponent_handles: Vec<String>, 
        func_name: &String
    ) -> Gt {
        let mut sum = Gt::zero();
        
        // Compute \sum_i g_i^[x_i]
        for (base, exponent_handle) in bases.iter().zip(exponent_handles.iter()) {
            let my_share = self.get_wire(exponent_handle);
            let exponentiated = base.clone().mul(my_share);

            sum = sum.add(exponentiated);
        }

        self.add_gt_elements_from_all_parties(&sum, func_name).await
    }

    // secret-shared MSM, where scalars are secret shares. Outputs MSM in the clear.
    pub async fn exp_and_reveal_g1(
        &mut self, 
        bases: Vec<G1>, 
        exponent_handles: Vec<String>, 
        func_name: &String
    ) -> G1 {
        let mut sum = G1::zero();
        
        // Compute \sum_i g_i^[x_i]
        for (base, exponent_handle) in bases.iter().zip(exponent_handles.iter()) {
            let my_share = self.get_wire(exponent_handle);
            let exponentiated = base.clone().mul(my_share).into_affine();

            sum = sum.add(exponentiated).into_affine();
        }

        self.add_g1_elements_from_all_parties(&sum, func_name).await
    }

    /// returns a^64
    pub async fn exp(&mut self, input_label: &String) -> String {
        let mut tmp = input_label.clone();
        for _i in 0..6 {
            let (h_a, h_b, h_c) = self.beaver().await;
            tmp = self.mult(
                &tmp, 
                &tmp, 
                (&h_a, &h_b, &h_c)
            ).await;
        }

        let handle = compute_exp_wire_id(input_label);
        self.wire_shares.insert(handle.clone(), self.get_wire(&tmp));
        handle
    }

    pub fn get_wire(&self, handle: &String) -> F {
        self.wire_shares.get(handle).unwrap().clone()
    }

    pub async fn eval_proof(&mut self, f_handles: Vec<String>, z: F, f_name: String) -> G1 {
        // get shares
        let f_shares = f_handles
            .iter()
            .map(|h| self.get_wire(h))
            .collect::<Vec<F>>();

        // Compute f_polynomial
        let f_poly = utils::interpolate_poly_over_mult_subgroup(&f_shares);

        let divisor = DensePolynomial::from_coefficients_vec(vec![F::from(1), -z]);

        // Divide by (X-z)
        let (quotient, _remainder) = 
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&f_poly).into(),
                &(&divisor).into(),
            ).unwrap();

        let pi_poly = utils::commit_poly(&quotient);
        let pi = self.add_g1_elements_from_all_parties(&pi_poly, &f_name).await;

        pi
    }

    pub async fn eval_proof_with_share_poly(&mut self, share_poly: DensePolynomial<F>, z: F, f_name: String) -> G1 {
        // Compute f_polynomial
        let f_poly = share_poly;

        let divisor = DensePolynomial::from_coefficients_vec(vec![F::from(1), -z]);

        // Divide by (X-z)
        let (quotient, _remainder) = 
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&f_poly).into(),
                &(&divisor).into(),
            ).unwrap();

        let pi_poly = utils::commit_poly(&quotient);
        let pi = self.add_g1_elements_from_all_parties(&pi_poly, &f_name).await;

        pi
    }

    pub async fn dist_ibe_encrypt(
        &mut self, 
        msg_share_handle: &String, // [z1]
        mask_share_handle: &String, // [r]
        pk: &G2, 
        id: BigUint
    ) -> (G1, Gt) {
        // let msg_share = self.output_wire_in_exponent(msg_share_handle).await;
        // let mask_share = self.output_wire_in_exponent(mask_share_handle).await;
    
        // TODO: fix this. Need proper hash to curve
        let x_f = F::from(id);
        let hash_id = G1::generator().mul(x_f);

        let h = <Curve as Pairing>::pairing(hash_id, pk);
    
        let c1 = self.exp_and_reveal_g1(
            vec![<Curve as Pairing>::G1Affine::generator()], 
            vec![mask_share_handle.clone()], 
            &String::from("c1_".to_owned() + msg_share_handle + mask_share_handle)
        ).await;
        
        let c2 = self.exp_and_reveal_gt(
            vec![Gt::generator(), h.clone()], 
            vec![msg_share_handle.clone(), mask_share_handle.clone()], 
            &String::from("c2".to_owned() + msg_share_handle + mask_share_handle)
        ).await;
    
        (c1, c2)
    }

    //returns the handle which 
    fn process_next_message(&mut self, msg: &EvalNetMsg) {
        match msg {
            EvalNetMsg::SendTriple { 
                sender: _sender,
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
                let a_i = decode_bs58_str_as_f(share_a);
                let b_i = decode_bs58_str_as_f(share_b);
                let c_i = decode_bs58_str_as_f(share_c);
                // store what we received
                self.wire_shares.insert(handle_a.clone(), a_i);
                self.wire_shares.insert(handle_b.clone(), b_i);
                self.wire_shares.insert(handle_c.clone(), c_i);
            },
            EvalNetMsg::PublishValue { 
                sender,
                handle,
                value
            } => {
                // if already exists, then ignore
                if self.mailbox.contains_key(handle) {
                    let sender_exists_for_handle = self.mailbox
                        .get(handle)
                        .unwrap()
                        .contains_key(sender);
                    if sender_exists_for_handle { return; } //ignore duplicate msg!
                } else {
                    //mailbox never got a message by this handle so lets make room for it
                    self.mailbox.insert(handle.clone(), HashMap::new());
                }

                self.mailbox
                    .get_mut(handle)
                    .unwrap()
                    .insert(sender.clone(), value.clone());
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

    async fn collect_messages_from_all_peers(
        &mut self, 
        identifier: &String
    ) -> Vec<String> {
        let mut messages = vec![];
        let peers: Vec<Pok3rPeerId> = self.addr_book.keys().cloned().collect();
        for peer_id in peers {
            if self.id.eq(&peer_id) { continue; }

            loop { //loop over all incoming messages till we find msg from peer
                if self.mailbox.contains_key(identifier) {
                    let sender_exists_for_handle = self.mailbox
                        .get(identifier)
                        .unwrap()
                        .contains_key(&peer_id);
                     //if we already have it, break out!
                    if sender_exists_for_handle { break; }
                }

                let msg: EvalNetMsg = self.rx.select_next_some().await;
                self.process_next_message(&msg);
            }

            // if we got here, we can assume we have the message from peer_id
            let msg = self.mailbox
                .get(identifier)
                .unwrap()
                .get(&peer_id)
                .unwrap()
                .clone();
            
            messages.push(msg);
        }

        //clear the mailbox because we might want to use identifier again
        self.mailbox.remove(identifier);

        messages
    }

}


fn encode_f_as_bs58_str(value: &F) -> String {
    let mut buffer: Vec<u8> = Vec::new();
    value.serialize_compressed(&mut buffer).unwrap();
    bs58::encode(buffer).into_string()
}

fn decode_bs58_str_as_f(msg: &String) -> F {
    let buf: Vec<u8> = bs58::decode(msg).into_vec().unwrap();
    F::deserialize_compressed(buf.as_slice()).unwrap()
}

fn encode_g1_as_bs58_str(value: &G1) -> String {
    let mut serialized_msg: Vec<u8> = Vec::new();
    value.serialize_compressed(&mut serialized_msg).unwrap();
    bs58::encode(serialized_msg).into_string()
}

fn decode_bs58_str_as_g1(msg: &String) -> G1 {
    let decoded = bs58::decode(msg).into_vec().unwrap();
    G1::deserialize_compressed(&mut Cursor::new(decoded)).unwrap()
}

fn encode_gt_as_bs58_str(value: &Gt) -> String {
    let mut serialized_msg: Vec<u8> = Vec::new();
    value.serialize_compressed(&mut serialized_msg).unwrap();
    bs58::encode(serialized_msg).into_string()
}

fn decode_bs58_str_as_gt(msg: &String) -> Gt {
    let decoded = bs58::decode(msg).into_vec().unwrap();
    Gt::deserialize_compressed(&mut Cursor::new(decoded)).unwrap()
}



pub async fn perform_sanity_testing(evaluator: &mut Evaluator) {
    println!("-------------- Running some sanity tests -----------------");

    println!("testing beaver triples...");
    let (h_a, h_b, h_c) = evaluator.beaver().await;
    let a = evaluator.output_wire(&h_a).await;
    let b = evaluator.output_wire(&h_b).await;
    let c = evaluator.output_wire(&h_c).await;
    assert_eq!(c, a * b);

    println!("testing adder...");
    let h_r1 = evaluator.ran();
    let h_r2 = evaluator.ran();
    let r1 = evaluator.output_wire(&h_r1).await;
    let r2 = evaluator.output_wire(&h_r2).await;
    let h_sum_r1_r2 = evaluator.add(&h_r1, &h_r2);
    let sum_r1_r2 = evaluator.output_wire(&h_sum_r1_r2).await;
    assert_eq!(sum_r1_r2, r1 + r2);

    println!("testing multiplier...");
    let h_mult_r1_r2 = evaluator.mult(&h_r1, &h_r2, (&h_a, &h_b, &h_c)).await;
    let mult_r1_r2 = evaluator.output_wire(&h_mult_r1_r2).await;
    assert_eq!(mult_r1_r2, r1 * r2);

    println!("testing inverter...");
    let (h_a, h_b, h_c) = evaluator.beaver().await;
    let h_r3 = evaluator.ran();
    let h_r4 = evaluator.ran();
    let r3 = evaluator.output_wire(&h_r3).await;
    let h_r3_inverted = evaluator.inv(&h_r3, &h_r4, (&h_a, &h_b, &h_c)).await;
    let r3_inverted = evaluator.output_wire(&h_r3_inverted).await;
    assert_eq!(ark_bls12_377::Fr::from(1), r3 * r3_inverted);

    println!("testing exponentiator...");
    let h_r = evaluator.ran();
    let r = evaluator.output_wire(&h_r).await;
    let h_r_exp_64 = evaluator.exp(&h_r).await;
    let r_exp_64 = evaluator.output_wire(&h_r_exp_64).await;
    assert_eq!(r.pow([64]), r_exp_64);

    println!("testing scale...");
    let h_r = evaluator.ran();
    let r = evaluator.output_wire(&h_r).await;
    let h_r_scaled = evaluator.scale(&h_r, F::from(42));
    let r_scaled = evaluator.output_wire(&h_r_scaled).await;
    assert_eq!(r * F::from(42), r_scaled);

    println!("testing output_wire and output_wire_in_exponent...");
    let h_r = evaluator.ran();
    let g_pow_r = evaluator.output_wire_in_exponent(&h_r).await;
    let r = evaluator.output_wire(&h_r).await;
    let g = <Curve as Pairing>::G1Affine::generator().clone();
    assert_eq!(g_pow_r, g.mul(&r));
}