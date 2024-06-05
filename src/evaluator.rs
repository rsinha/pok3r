
use ark_bls12_377::{ G1Projective, G2Projective };
use ark_ec::{Group, pairing::*};
use ark_poly::DenseUVPolynomial;
use ark_poly::univariate::DenseOrSparsePolynomial;
use ark_poly::univariate::DensePolynomial;
use ark_std::UniformRand;
use ark_ff::{Field, /* FftField */ };
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_std::{Zero, One};
use std::collections::HashMap;
use std::ops::*;
use futures::{prelude::*, channel::*};
use ark_std::io::Cursor;
//use rand::{rngs::StdRng, SeedableRng};
use sha2::{Sha256, Digest};
use num_bigint::BigUint;
use rand::{rngs::StdRng, SeedableRng};

use crate::address_book::*;
use crate::common::*;
use crate::kzg::UniversalParams;
use crate::utils;

pub type Curve = ark_bls12_377::Bls12_377;
//type KZG = KZG10::<Curve, DensePolynomial<<Curve as Pairing>::ScalarField>>;
pub type F = ark_bls12_377::Fr;
pub type Gt = PairingOutput<Curve>;
pub type G1 = G1Projective;
pub type G2 = G2Projective;

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
    /// stores incoming messages indexed by identifier and then by peer id
    mailbox: HashMap<String, HashMap<String, String>>,
    /// keep track of gates
    gate_counter: u64,
    /// keep track of the number of beaver triples consumed
    beaver_counter: u64
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
            gate_counter: 0,
            beaver_counter: 0
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

    fn compute_fresh_wire_label(&mut self) -> String {
        self.gate_counter += 1;

        //gate_id denotes a unique identifier for this gate
        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(&self.gate_counter.to_be_bytes());
    
        let mut hasher = Sha256::new();
        hasher.update(&hasher_input);
        let hash = hasher.finalize();
    
        bs58::encode(hash).into_string()
    }

    /// Return the number of beaver triples consumed
    pub fn get_beaver_counter(&self) -> u64 {
        self.beaver_counter
    }
    

    /// asks the pre-processor to generate an additive sharing of a random value
    /// returns a string handle, which can be used to access the share in future
    pub fn ran(&mut self) -> String {
        let r = F::rand(&mut rand::thread_rng());

        let handle = self.compute_fresh_wire_label();
        self.wire_shares.insert(handle.clone(), r);
        handle
    }

    /// returns shares of a random element in {1, ω, ..., ω^63}
    pub async fn ran_64(&mut self, h_a: &String) -> String {
        let h_c =  self.compute_fresh_wire_label();

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

    pub async fn batch_ran_64(&mut self, len: usize) -> Vec<String> {
        let mut h_c = Vec::new();
        let h_as = (0..len)
            .into_iter()
            .map(|_| self.ran())
            .collect::<Vec<String>>();

        let h_a_exp_64s = self.batch_exp(&h_as).await;
        let a_exp_64s = self.batch_output_wire(&h_a_exp_64s).await;

        for i in 0..len {
            if a_exp_64s[i] == F::from(0) {
                panic!("Highly improbable event occurred. Abort!");
            }
        
            let mut l = a_exp_64s[i];
            for _ in 0..LOG_PERM_SIZE {
                l = utils::compute_root(&l);
            }

            let handle = self.compute_fresh_wire_label();
            let share_c = self.get_wire(&h_as[i]) / l;
            self.wire_shares.insert(handle.clone(), share_c);
            h_c.push(handle);
        }

        h_c
    }

    /// outputs the wire label denoting the [x] + [y]
    pub fn add(&mut self, 
        handle_x: &String, 
        handle_y: &String) -> String {
        let handle =  self.compute_fresh_wire_label();

        let share_x = self.get_wire(handle_x);
        let share_y = self.get_wire(handle_y);

        self.wire_shares.insert(handle.clone(), share_x + share_y);
        handle
    }

    /// outputs the wire label denoting the [x] - [y]
    pub fn sub(&mut self, 
        handle_x: &String, 
        handle_y: &String) -> String {
        let handle =  self.compute_fresh_wire_label();

        let share_x = self.get_wire(handle_x);
        let share_y = self.get_wire(handle_y);

        self.wire_shares.insert(handle.clone(), share_x - share_y);
        handle
    }
    
    pub async fn inv(&mut self, 
        handle_in: &String
    ) -> String {
        // goal: compute inv([s])
        // step 1: invoke ran_p to obtain [r]
        // step 2: invoke mult to get [q] = [r . s]
        // step 3: reconstruct q = r . s
        // step 4: return [r] / q
        
        let handle_r = self.ran();
        let handle_out = self.compute_fresh_wire_label();
        
        let handle_r_mult_s = self.mult(
            handle_in, 
            &handle_r).await;
        //reconstruct the padded wires in the clear
        let r_mult_s = self.output_wire(&handle_r_mult_s).await;

        let q_inv = F::from(1) / r_mult_s;
        let wire_out = q_inv * self.get_wire(&handle_r);

        self.wire_shares.insert(handle_out.clone(), wire_out);

        handle_out
    }

    pub async fn batch_inv(&mut self, 
        input_handles: &[String]
    ) -> Vec<String> {
        // goal: compute inv([s])
        // step 1: invoke ran_p to obtain [r]
        // step 2: invoke mult to get [q] = [r . s]
        // step 3: reconstruct q = r . s
        // step 4: return [r] / q
        
        let rand_handles: Vec<String> = (0..input_handles.len())
            .into_iter()
            .map(|_| self.ran())
            .collect();

        let masked_handles = self.batch_mult(
            input_handles, 
            &rand_handles
        ).await;
        
        let masked_values = self.batch_output_wire(&masked_handles).await;

        let mut output: Vec<String> = vec![];
        for i in 0..input_handles.len() {
            let q_inv = F::from(1) / masked_values[i];
            let wire_out = q_inv * self.get_wire(&rand_handles[i]);

            let handle_out = self.compute_fresh_wire_label();
            self.wire_shares.insert(handle_out.clone(), wire_out);

            output.push(handle_out);
        }

        output
    }

    // Adds [x] to y in the clear and outputs handle to the resulting share
    pub fn clear_add(&mut self,
        handle_x: &String,
        y: F
    ) -> String {
        let handle_out = self.compute_fresh_wire_label();

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
        let handle_out = self.compute_fresh_wire_label();

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
        handle_y: &String
    ) -> String {
        let (h_a, h_b, h_c) = self.beaver().await;

        let share_a = self.get_wire(&h_a);
        let share_b = self.get_wire(&h_b);
        let share_c = self.get_wire(&h_c);

        // our strategy would be to re-use other components
        //construct adder gates for the padded wires
        let handle_x_plus_a = self.add(handle_x, &h_a);
        let handle_y_plus_b = self.add(handle_y, &h_b);

        //reconstruct the padded wires in the clear
        let x_plus_a = self.output_wire(&handle_x_plus_a).await;
        let y_plus_b = self.output_wire(&handle_y_plus_b).await;

        let handle = self.compute_fresh_wire_label();
        
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

    pub async fn batch_mult(&mut self, 
        x_handles: &[String], 
        y_handles: &[String]
    ) -> Vec<String> {

        assert_eq!(x_handles.len(), y_handles.len());
        let len: usize = x_handles.len();

        // store all beaver triples for use later in this function
        let mut bookkeeping_a: Vec<F> = Vec::new();
        let mut bookkeeping_b: Vec<F> = Vec::new();
        let mut bookkeeping_c: Vec<F> = Vec::new();
        // store all handles for [x+a] and [y+b]
        let mut x_plus_a_handles: Vec<String> = Vec::new();
        let mut y_plus_b_handles: Vec<String> = Vec::new();

        let beavers = self.batch_beaver(len);

        for i in 0..len {
            let (h_a, h_b, h_c) = beavers[i].clone();

            bookkeeping_a.push(self.get_wire(&h_a));
            bookkeeping_b.push(self.get_wire(&h_b));
            bookkeeping_c.push(self.get_wire(&h_c));

            let handle_x_plus_a = self.add(&x_handles[i], &h_a);
            let handle_y_plus_b = self.add(&y_handles[i], &h_b);

            x_plus_a_handles.push(handle_x_plus_a);
            y_plus_b_handles.push(handle_y_plus_b);
        }

        // let x_plus_a_reconstructed = self
        //     .batch_output_wire(&x_plus_a_handles)
        //     .await;

        // let y_plus_b_reconstructed = self
        //     .batch_output_wire(&y_plus_b_handles)
        //     .await;

        let mut batch_handles = vec![];
        batch_handles.extend_from_slice(&x_plus_a_handles);
        batch_handles.extend_from_slice(&y_plus_b_handles);

        let x_plus_a_and_y_plus_b = self.batch_output_wire(&batch_handles).await;

        let mut output: Vec<String> = vec![];
        let my_id = get_node_id_via_peer_id(&self.addr_book, &self.id).unwrap();
        for i in 0..len {
            let x_plus_a_reconstructed = x_plus_a_and_y_plus_b[i];
            let y_plus_b_reconstructed = x_plus_a_and_y_plus_b[x_plus_a_handles.len() + i];

            //only one party should add the constant term
            let share_x_mul_y: F = match my_id {
                0 => {
                    x_plus_a_reconstructed * y_plus_b_reconstructed 
                    - x_plus_a_reconstructed * bookkeeping_b[i] 
                    - y_plus_b_reconstructed * bookkeeping_a[i]  
                    + bookkeeping_c[i]
                },
                _ => {
                    F::from(0)
                    - x_plus_a_reconstructed * bookkeeping_b[i] 
                    - y_plus_b_reconstructed* bookkeeping_a[i] 
                    + bookkeeping_c[i]
                }
            };

            let h = self.compute_fresh_wire_label();
            self.wire_shares.insert(h.clone(), share_x_mul_y);

            output.push(h.clone());
        }

        output
    }

    pub fn fixed_wire_handle(&mut self, value: F) -> String {
        let handle = self.compute_fresh_wire_label();
        
        let my_id = get_node_id_via_peer_id(&self.addr_book, &self.id).unwrap();
        let share: F = match my_id {
            0 => value,
            _ => F::from(0)
        };

        self.wire_shares.insert(handle.clone(), share);
        handle
    }

    /// PolyEval takes as input a shared polynomial f(x) and a point x and returns share of f(x)
    pub fn share_poly_eval(&mut self, 
        f_poly_share: &DensePolynomial<F>,
        x: F,
     ) -> String {

        let handle_out = self.compute_fresh_wire_label();

        let mut sum = F::zero();
        let mut x_pow = F::one();
        for coeff in f_poly_share.coeffs.iter() {
            sum += coeff * &x_pow;
            x_pow *= x;
        }

        self.wire_shares.insert(handle_out.clone(), sum);
        handle_out

    }

    /// Should multiply two polynomials with shared coefficients to get a larger degree polynomial with shared coefficients
    pub async fn share_poly_mult(&mut self, 
        f_poly_share: DensePolynomial<F>,
        g_poly_share: DensePolynomial<F>,
     ) -> DensePolynomial<F> {
        let alpha = utils::multiplicative_subgroup_of_size(2*PERM_SIZE as u64);
        let powers_of_alpha: Vec<F> = (0..2*PERM_SIZE)
            .into_iter()
            .map(|i| utils::compute_power(&alpha, i as u64))
            .collect();

        let mut f_evals = Vec::new();
        let mut g_evals = Vec::new();

        for i in 0..2*PERM_SIZE {
            f_evals.push(self.share_poly_eval(&f_poly_share, powers_of_alpha[i]));
            g_evals.push(self.share_poly_eval(&g_poly_share, powers_of_alpha[i]));
        }

        // Compute h_evals from f_evals and g_evals using Beaver mult
        let h_evals = self.batch_mult(&f_evals, &g_evals).await
            .into_iter()
            .map(|x| self.get_wire(&x))
            .collect::<Vec<F>>();

        // Interpolate h_evals to get h_poly_share
        let h_poly_share = utils::interpolate_poly_over_mult_subgroup(&h_evals);

        h_poly_share
    }

    pub async fn beaver(&mut self) -> (String, String, String) {
        // Update beaver counter
        self.beaver_counter += 1;

        let n: usize = self.addr_book.len();
        let my_id = get_node_id_via_peer_id(&self.addr_book, &self.id).unwrap();

        let handle_a = self.compute_fresh_wire_label();
        let handle_b = self.compute_fresh_wire_label();
        let handle_c = self.compute_fresh_wire_label();

        let mut seeded_rng = StdRng::from_seed([42u8; 32]);

        let mut sum_a = F::from(0);
        let mut sum_b = F::from(0);
        let mut sum_c = F::from(0);

        for i in 1..n {
            let party_i_share_a =  F::rand(&mut seeded_rng);
            let party_i_share_b =  F::rand(&mut seeded_rng);
            let party_i_share_c =  F::rand(&mut seeded_rng);

            sum_a += party_i_share_a;
            sum_b += party_i_share_b;
            sum_c += party_i_share_c;

            if i == (my_id as usize) {
                self.wire_shares.insert(handle_a.clone(), party_i_share_a);
                self.wire_shares.insert(handle_b.clone(), party_i_share_b);
                self.wire_shares.insert(handle_c.clone(), party_i_share_c);
            }
        }

        if my_id == 0 {
            self.wire_shares.insert(handle_a.clone(), F::from(0) - sum_a);
            self.wire_shares.insert(handle_b.clone(), F::from(0) - sum_b);
            self.wire_shares.insert(handle_c.clone(), F::from(0) - sum_c);
        }

        (handle_a, handle_b, handle_c)
    }

    pub fn batch_beaver(&mut self, num_beavers: usize) -> Vec<(String, String, String)> {
        // Update beaver counter
        self.beaver_counter += num_beavers as u64;

        let n: usize = self.addr_book.len();
        let my_id = get_node_id_via_peer_id(&self.addr_book, &self.id).unwrap();

        let mut seeded_rng = StdRng::from_seed([42u8; 32]);

        let handles_a: Vec<String> = (0..num_beavers)
            .into_iter()
            .map(|_| self.compute_fresh_wire_label())
            .collect();
        let handles_b: Vec<String> = (0..num_beavers)
            .into_iter()
            .map(|_| self.compute_fresh_wire_label())
            .collect();
        let handles_c: Vec<String> = (0..num_beavers)
            .into_iter()
            .map(|_| self.compute_fresh_wire_label())
            .collect();

        let mut sum_a = vec![F::from(0); num_beavers];
        let mut sum_b = vec![F::from(0); num_beavers];
        let mut sum_c = vec![F::from(0); num_beavers];

        for i in 0..num_beavers {
            for j in 1..n {
                let party_j_share_a =  F::rand(&mut seeded_rng);
                let party_j_share_b =  F::rand(&mut seeded_rng);
                let party_j_share_c =  F::rand(&mut seeded_rng);

                sum_a[i] += party_j_share_a;
                sum_b[i] += party_j_share_b;
                sum_c[i] += party_j_share_c;

                if j == (my_id as usize) {
                    self.wire_shares.insert(handles_a[i].clone(), party_j_share_a);
                    self.wire_shares.insert(handles_b[i].clone(), party_j_share_b);
                    self.wire_shares.insert(handles_c[i].clone(), party_j_share_c);
                }
            }

            if my_id == 0 {
                self.wire_shares.insert(handles_a[i].clone(), F::from(0) - sum_a[i]);
                self.wire_shares.insert(handles_b[i].clone(), F::from(0) - sum_b[i]);
                self.wire_shares.insert(handles_c[i].clone(), F::from(0) - sum_c[i]);
            }
        }

        let mut output = Vec::new();
        for i in 0..num_beavers {
            output.push((handles_a[i].clone(), handles_b[i].clone(), handles_c[i].clone()));
        }

        output
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

        let sum = incoming_values
            .iter()
            .fold(my_share, |acc, v| acc + v);
        sum
    }

    /*
     * outputs the reconstructed value of all wires
     */
    pub async fn batch_output_wire(&mut self, wire_handles: &[String]) -> Vec<F> {
        let mut outputs = Vec::new();

        let mut handles = Vec::new();
        let mut values = Vec::new();

        let len = wire_handles.len();

        for i in 0..len {
            handles.push(wire_handles[i].clone());
            values.push(encode_f_as_bs58_str(&self.get_wire(&wire_handles[i])));
        }

        if len > 256 {
            let mut processed_len = 0;

            while processed_len < len {
                let this_iter_len = std::cmp::min(len - processed_len, 256);
                let handles_bucket = &handles[processed_len..processed_len + this_iter_len].to_vec();
                let values_bucket = &values[processed_len..processed_len + this_iter_len].to_vec();

                let msg = EvalNetMsg::PublishBatchValue {
                    sender: self.id.clone(),
                    handles: handles_bucket.to_owned(),
                    values: values_bucket.to_owned(),
                };
                send_over_network!(msg, self.tx);

                processed_len += this_iter_len;
            }
        } else {
            let msg = EvalNetMsg::PublishBatchValue {
                sender: self.id.clone(),
                handles: handles,
                values: values,
            };
            send_over_network!(msg, self.tx);
        }

        for i in 0..len {
            let incoming_msgs = self.collect_messages_from_all_peers(&wire_handles[i]).await;
            let incoming_values: Vec<F> = incoming_msgs
                .into_iter()
                .map(|x| decode_bs58_str_as_f(&x))
                .collect();

            let sum = incoming_values
                .iter()
                .fold(self.get_wire(&wire_handles[i]), |acc, v| acc + v);

            outputs.push(sum);
        }

        outputs
    }

    // //on input wire [x], this outputs g^[x], and reconstructs and outputs g^x
    // we will use G1
    pub async fn output_wire_in_exponent(&mut self, wire_handle: &String) -> G1 {
        let my_share = self.get_wire(wire_handle);
        let g = <Curve as Pairing>::G1Affine::generator();
        let my_share_exp = g.clone().mul(my_share);
        
        self.add_g1_elements_from_all_parties(
            &my_share_exp, 
            wire_handle
        ).await
    }

    pub async fn batch_output_wire_in_exponent(&mut self, wire_handles: &[String]) -> Vec<G1> {
        let mut my_share_exps = Vec::new();
        let g = G1::generator();
        for i in 0..wire_handles.len() {
            let my_share = self.get_wire(&wire_handles[i]);
            let my_share_exp = g.clone().mul(my_share);
            my_share_exps.push(my_share_exp);
        }

        self.batch_add_g1_elements_from_all_parties(
            &my_share_exps, 
            wire_handles
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
        for v in incoming_values { sum = sum.add(v); }
        sum
    }

    pub async fn batch_add_g1_elements_from_all_parties(
        &mut self,
        inputs: &[G1],
        identifiers: &[String]
    ) -> Vec<G1> {
        assert_eq!(inputs.len(), identifiers.len());
        let len = inputs.len();

        let mut outputs = Vec::new();

        let values = inputs
            .into_iter()
            .map(|e| encode_g1_as_bs58_str(e))
            .collect::<Vec<String>>();

        if len > 256 {
            let mut processed_len = 0;

            while processed_len < len {
                let this_iter_len = std::cmp::min(len - processed_len, 256);
                let handles_bucket = &identifiers[processed_len..processed_len + this_iter_len].to_vec();
                let values_bucket = &values[processed_len..processed_len + this_iter_len].to_vec();

                let msg = EvalNetMsg::PublishBatchValue {
                    sender: self.id.clone(),
                    handles: handles_bucket.to_owned(),
                    values: values_bucket.to_owned(),
                };
                send_over_network!(msg, self.tx);

                processed_len += this_iter_len;
            }
        }
        else {
            let msg = EvalNetMsg::PublishBatchValue {
                sender: self.id.clone(),
                handles: identifiers.into(),
                values: values,
            };
            send_over_network!(msg, self.tx);
        }

        for i in 0..inputs.len() {
            let incoming_msgs = self.collect_messages_from_all_peers(&identifiers[i]).await;
            let incoming_values: Vec<G1> = incoming_msgs
                .into_iter()
                .map(|x| decode_bs58_str_as_g1(&x))
                .collect();

            let sum = incoming_values
                .iter()
                .fold(inputs[i], |acc, v| acc.add(v));

            outputs.push(sum);
        }

        outputs
    }

    pub async fn add_g2_elements_from_all_parties(
        &mut self, value: &G2, 
        identifier: &String
    ) -> G2 {

        let msg = EvalNetMsg::PublishValue {
            sender: self.id.clone(),
            handle: identifier.clone(),
            value: encode_g2_as_bs58_str(value),
        };
        send_over_network!(msg, self.tx);

        let incoming_msgs = self.collect_messages_from_all_peers(identifier).await;

        let incoming_values: Vec<G2> = incoming_msgs
            .into_iter()
            .map(|x| decode_bs58_str_as_g2(&x))
            .collect();

        let mut sum: G2 = value.clone();
        for v in incoming_values { sum = sum.add(v); }
        sum
    }

    pub async fn batch_add_g2_elements_from_all_parties(
        &mut self,
        inputs: &[G2],
        identifiers: &[String]
    ) -> Vec<G2> {
        assert_eq!(inputs.len(), identifiers.len());

        let len = inputs.len();

        let mut outputs = Vec::new();

        let values = inputs
            .into_iter()
            .map(|e| encode_g2_as_bs58_str(e))
            .collect::<Vec<String>>();

        if len > 256 {
            let mut processed_len = 0;

            while processed_len < len {
                let this_iter_len = std::cmp::min(len - processed_len, 256);
                let handles_bucket = &identifiers[processed_len..processed_len + this_iter_len].to_vec();
                let values_bucket = &values[processed_len..processed_len + this_iter_len].to_vec();

                let msg = EvalNetMsg::PublishBatchValue {
                    sender: self.id.clone(),
                    handles: handles_bucket.to_owned(),
                    values: values_bucket.to_owned(),
                };
                send_over_network!(msg, self.tx);

                processed_len += this_iter_len;
            }
        }
        else {
            let msg = EvalNetMsg::PublishBatchValue {
                sender: self.id.clone(),
                handles: identifiers.into(),
                values: values,
            };
            send_over_network!(msg, self.tx);
        }

        for i in 0..inputs.len() {
            let incoming_msgs = self.collect_messages_from_all_peers(&identifiers[i]).await;
            let incoming_values: Vec<G2> = incoming_msgs
                .into_iter()
                .map(|x| decode_bs58_str_as_g2(&x))
                .collect();

            let sum = incoming_values
                .iter()
                .fold(inputs[i], |acc, v| acc.add(v));

            outputs.push(sum);
        }

        outputs
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

    pub async fn batch_add_gt_elements_from_all_parties(
        &mut self,
        inputs: &[Gt],
        identifiers: &[String]
    ) -> Vec<Gt> {
        assert_eq!(inputs.len(), identifiers.len());

        let len = inputs.len();

        let mut outputs = Vec::new();

        let values = inputs
            .into_iter()
            .map(|e| encode_gt_as_bs58_str(e))
            .collect::<Vec<String>>();

        if len > 64 {
            let mut processed_len = 0;

            while processed_len < len {
                let this_iter_len = std::cmp::min(len - processed_len, 64);
                let handles_bucket = &identifiers[processed_len..processed_len + this_iter_len].to_vec();
                let values_bucket = &values[processed_len..processed_len + this_iter_len].to_vec();

                let msg = EvalNetMsg::PublishBatchValue {
                    sender: self.id.clone(),
                    handles: handles_bucket.to_owned(),
                    values: values_bucket.to_owned(),
                };
                send_over_network!(msg, self.tx);

                processed_len += this_iter_len;
            }
        }
        else {
            let msg = EvalNetMsg::PublishBatchValue {
                sender: self.id.clone(),
                handles: identifiers.into(),
                values: values,
            };
            send_over_network!(msg, self.tx);
        }

        for i in 0..inputs.len() {
            let incoming_msgs = self.collect_messages_from_all_peers(&identifiers[i]).await;
            let incoming_values: Vec<Gt> = incoming_msgs
                .into_iter()
                .map(|x| decode_bs58_str_as_gt(&x))
                .collect();

            let sum = incoming_values
                .iter()
                .fold(inputs[i], |acc, v| acc.add(v));

            outputs.push(sum);
        }

        outputs
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

    pub async fn batch_exp_and_reveal_gt(
        &mut self, 
        bases: Vec<Vec<Gt>>,
        exponent_handles: Vec<Vec<String>>,
        identifiers: Vec<String>
    ) -> Vec<Gt> {
        let len = bases.len();

        assert_eq!(len, exponent_handles.len());
        assert_eq!(len, identifiers.len());

        let mut group_elements = vec![];

        for i in 0..len {
            let msm_input = bases[i].iter().zip(exponent_handles[i].iter());
            let mut sum = Gt::zero();

            for (base, exponent_handle) in msm_input {
                let exponent = self.get_wire(exponent_handle);

                if exponent == F::from(1) {
                    sum = sum.add(base);
                }
                else {
                    sum = sum.add(base.mul(self.get_wire(exponent_handle)));
                }
            }

            group_elements.push(sum);
        }

        self.batch_add_gt_elements_from_all_parties(&group_elements, &identifiers).await
    }

    // secret-shared MSM, where scalars are secret shares. Outputs MSM in the clear.
    pub async fn exp_and_reveal_g1(
        &mut self, 
        bases: Vec<G1>, 
        exponent_handles: Vec<String>, 
        identifier: &String
    ) -> G1 {
        let mut sum = G1::zero();
        
        // Compute \sum_i g_i^[x_i]
        for (base, exponent_handle) in bases.iter().zip(exponent_handles.iter()) {
            let my_share = self.get_wire(exponent_handle);
            let exponentiated = base.clone().mul(my_share);

            sum = sum.add(exponentiated);
        }

        self.add_g1_elements_from_all_parties(&sum, identifier).await
    }

    pub async fn batch_exp_and_reveal_g1(
        &mut self, 
        bases: Vec<Vec<G1>>,
        exponent_handles: Vec<Vec<String>>,
        identifiers: Vec<String>
    ) -> Vec<G1> {
        let len = bases.len();

        assert_eq!(len, exponent_handles.len());
        assert_eq!(len, identifiers.len());

        let mut group_elements = vec![];

        for i in 0..len {
            let msm_input = bases[i].iter().zip(exponent_handles[i].iter());
            let mut sum = G1::zero();

            for (base, exponent_handle) in msm_input {
                let exponentiated = base.mul(self.get_wire(exponent_handle));
                sum = sum.add(exponentiated);
            }

            group_elements.push(sum);
        }

        self.batch_add_g1_elements_from_all_parties(&group_elements, &identifiers).await
    }

    pub async fn exp_and_reveal_g2(
        &mut self, 
        bases: Vec<G2>, 
        exponent_handles: Vec<String>, 
        identifier: &String
    ) -> G2 {
        let mut sum = G2::zero();
        
        // Compute \sum_i g_i^[x_i]
        for (base, exponent_handle) in bases.iter().zip(exponent_handles.iter()) {
            let my_share = self.get_wire(exponent_handle);
            let exponentiated = base.clone().mul(my_share);

            sum = sum.add(exponentiated);
        }

        self.add_g2_elements_from_all_parties(&sum, identifier).await
    }

    pub async fn batch_exp_and_reveal_g2(
        &mut self, 
        bases: Vec<Vec<G2>>,
        exponent_handles: Vec<Vec<String>>,
        identifiers: Vec<String>
    ) -> Vec<G2> {
        let len = bases.len();

        assert_eq!(len, exponent_handles.len());
        assert_eq!(len, identifiers.len());

        let mut group_elements = vec![];

        for i in 0..len {
            let msm_input = bases[i].iter().zip(exponent_handles[i].iter());
            let mut sum = G2::zero();

            for (base, exponent_handle) in msm_input {
                let exponentiated = base.mul(self.get_wire(exponent_handle));
                sum = sum.add(exponentiated);
            }

            group_elements.push(sum);
        }

        self.batch_add_g2_elements_from_all_parties(&group_elements, &identifiers).await
    }

    /// returns a^64
    pub async fn exp(&mut self, input_label: &String) -> String {
        let mut tmp = input_label.clone();
        for _i in 0..6 {
            tmp = self.mult(
                &tmp, 
                &tmp
            ).await;
        }

        let handle = self.compute_fresh_wire_label();
        self.wire_shares.insert(handle.clone(), self.get_wire(&tmp));
        handle
    }

    pub async fn batch_exp(&mut self, input_labels: &[String]) -> Vec<String> {
        let mut tmp = input_labels.to_vec();
        for _i in 0..LOG_PERM_SIZE {
            tmp = self.batch_mult(
                &tmp, 
                &tmp
            ).await;
        }

        let mut output = Vec::new();
        for i in 0..input_labels.len() {
            let handle = self.compute_fresh_wire_label();
            self.wire_shares.insert(handle.clone(), self.get_wire(&tmp[i]));
            output.push(handle);
        }

        output
    }

    pub fn get_wire(&self, handle: &String) -> F {
        self.wire_shares.get(handle).unwrap().clone()
    }

    pub async fn eval_proof(&mut self, pp: &UniversalParams<Curve>, f_handles: Vec<String>, z: F, f_name: String) -> G1 {
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

        let pi_poly = utils::commit_poly(pp, &quotient);
        let pi = self.add_g1_elements_from_all_parties(&pi_poly, &f_name).await;

        pi
    }

    pub async fn eval_proof_with_share_poly(&mut self, pp: &UniversalParams<Curve>, share_poly: DensePolynomial<F>, z: F) -> G1 {
        // Compute f_polynomial
        let f_poly = share_poly;

        let divisor = DensePolynomial::from_coefficients_vec(vec![-z, F::from(1)]);

        // Divide by (X-z)
        let (quotient, _remainder) = 
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&f_poly).into(),
                &(&divisor).into(),
            ).unwrap();

        let pi_poly = utils::commit_poly(pp, &quotient);
        // let pi = self.add_g1_elements_from_all_parties(&pi_poly, &f_name).await;

        pi_poly
    }

    pub async fn batch_eval_proof_with_share_poly(
        &mut self, 
        pp: &UniversalParams<Curve>, 
        share_polys: &Vec<DensePolynomial<F>>, 
        z_s: &Vec<F>
    ) -> Vec<G1> {
        let len = share_polys.len();
        // assert_eq!(len, f_names.len());

        let mut pi_share_vec = Vec::new();
        for i in 0..len {
            // Compute f_polynomial
            let f_poly = share_polys[i].clone();

            let divisor = DensePolynomial::from_coefficients_vec(
                vec![-z_s[i], F::from(1)]
            );

            // Divide by (X-z_i)
            let (quotient, _remainder) = 
                DenseOrSparsePolynomial::divide_with_q_and_r(
                    &(&f_poly).into(),
                    &(&divisor).into(),
                ).unwrap();

            let pi_poly = utils::commit_poly(pp, &quotient);
            pi_share_vec.push(pi_poly);
        }

        pi_share_vec
        // self.batch_add_g1_elements_from_all_parties(&pi_share_vec, &f_names).await
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
            vec![G1::generator()], 
            vec![mask_share_handle.clone()], 
            &String::from("ibe_c1_".to_owned() + msg_share_handle + mask_share_handle)
        ).await;
        
        let c2 = self.exp_and_reveal_gt(
            vec![Gt::generator(), h.clone()], 
            vec![msg_share_handle.clone(), mask_share_handle.clone()], 
            &String::from("ibe_c2".to_owned() + msg_share_handle + mask_share_handle)
        ).await;
    
        (c1, c2)
    }

    pub async fn batch_dist_ibe_encrypt(
        &mut self, 
        msg_share_handles: &[String], // [z1]
        mask_share_handles: &[String], // [r]
        pk: &G2, 
        ids: &[BigUint]
    ) -> (Vec<G2>, Vec<Gt>) {
        assert_eq!(msg_share_handles.len(), mask_share_handles.len());

        // Compute e_i^r
        let e_is = ids
            .iter()
            .zip(mask_share_handles.iter())
            .map(|(id, mask)| {
                let x_f = F::from(id.clone());
                let hash_id_pow_r = G1::generator().mul(x_f).mul(self.get_wire(&mask));

                <Curve as Pairing>::pairing(hash_id_pow_r, pk)
            })
            .collect::<Vec<Gt>>();

        let c1s = self.batch_exp_and_reveal_g2(
            vec![vec![G2::generator()]; msg_share_handles.len()], 
            vec![mask_share_handles.to_vec(); PERM_SIZE], 
            msg_share_handles
                .iter()
                .map(|h| String::from("ibe_c1_".to_owned() + h))
                .collect::<Vec<String>>()
        ).await;

        // Vector of 64 elements, where the i^th element is a vector [g, e_i^r]
        let gt_with_e_is = (0..msg_share_handles.len())
            .into_iter()
            .map(|i| vec![Gt::generator(), e_is[i].clone()])
            .collect::<Vec<Vec<Gt>>>();

        // Vector of 64 elements, where the i^th element is a vector [msg_i, 1]
        let one_wire_handle = self.compute_fresh_wire_label();
        self.wire_shares.insert(one_wire_handle.clone(), F::one());

        let msg_mask_interleaved = msg_share_handles
            .iter()
            .zip(mask_share_handles.iter())
            .map(|(m, _)| vec![m.clone(), one_wire_handle.clone()])
            .collect::<Vec<Vec<String>>>();

        let c2s = self.batch_exp_and_reveal_gt(
            gt_with_e_is, 
            msg_mask_interleaved, 
            msg_share_handles
                .iter()
                .map(|h| String::from("ibe_c2".to_owned() + h))
                .collect::<Vec<String>>()
        ).await;

        (c1s, c2s)
    }

    /// Same as dist_batch_ibe_encrypt, but with common mask
    pub async fn batch_dist_ibe_encrypt_with_common_mask(
        &mut self, 
        msg_share_handles: &[String], // [z1]
        mask_share_handle: &String, // [r]
        pk: &G2, 
        ids: &[BigUint]
    ) -> (G2, Vec<Gt>) {
        // Compute e_i^r
        let e_is = ids
            .iter()
            .map(|id| {
                let x_f = F::from(id.clone());
                let hash_id_pow_r = G1::generator().mul(x_f).mul(self.get_wire(&mask_share_handle));

                <Curve as Pairing>::pairing(hash_id_pow_r, pk)
            })
            .collect::<Vec<Gt>>();

        let c1 = self.exp_and_reveal_g2(
            vec![G2::generator()], 
            vec![mask_share_handle.clone()], 
            &String::from("ibe_c1_".to_owned() + mask_share_handle)
        ).await;

        // Vector of 64 elements, where the i^th element is a vector [g, e_i^r]
        let gt_with_e_is = (0..msg_share_handles.len())
            .into_iter()
            .map(|i| vec![Gt::generator(), e_is[i].clone()])
            .collect::<Vec<Vec<Gt>>>();

        // Vector of 64 elements, where the i^th element is a vector [msg_i, 1]
        let one_wire_handle = self.compute_fresh_wire_label();
        self.wire_shares.insert(one_wire_handle.clone(), F::one());

        let msg_mask_interleaved = msg_share_handles
            .iter()
            .map(|m| vec![m.clone(), one_wire_handle.clone()])
            .collect::<Vec<Vec<String>>>();

        let c2s = self.batch_exp_and_reveal_gt(
            gt_with_e_is, 
            msg_mask_interleaved, 
            msg_share_handles
                .iter()
                .map(|h| String::from("ibe_c2".to_owned() + h))
                .collect::<Vec<String>>()
        ).await;

        (c1, c2s)
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
                self.accept_handle_and_value_from_sender(sender, handle, value);
            },
            EvalNetMsg::PublishBatchValue { 
                sender,
                handles,
                values
            } => {
                assert_eq!(handles.len(), values.len());

                for (h,v) in handles.iter().zip(values.iter()) {
                    self.accept_handle_and_value_from_sender(sender, h, v);
                }
            },
            _ => return,
        }
    }

    fn accept_handle_and_value_from_sender(&mut self, 
        sender: &String, 
        handle: &String, 
        value: &String
    ) {
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

fn encode_g2_as_bs58_str(value: &G2) -> String {
    let mut serialized_msg: Vec<u8> = Vec::new();
    value.serialize_compressed(&mut serialized_msg).unwrap();
    bs58::encode(serialized_msg).into_string()
}

fn decode_bs58_str_as_g2(msg: &String) -> G2 {
    let decoded = bs58::decode(msg).into_vec().unwrap();
    G2::deserialize_compressed(&mut Cursor::new(decoded)).unwrap()
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

    println!("testing batch output wire...");
    let mut a_handles = Vec::new();
    let mut b_handles = Vec::new();
    let mut c_handles = Vec::new();

    for _i in 0..5 {
        let (h_a, h_b, h_c) = evaluator.beaver().await;

        a_handles.push(h_a);
        b_handles.push(h_b);
        c_handles.push(h_c);
    }
    let reconstructed_a = evaluator.batch_output_wire(&a_handles).await;
    let reconstructed_b = evaluator.batch_output_wire(&b_handles).await;
    let reconstructed_c = evaluator.batch_output_wire(&c_handles).await;
    for i in 0..5 {
        let a = reconstructed_a.get(i).unwrap();
        let b = reconstructed_b.get(i).unwrap();
        let c = reconstructed_c.get(i).unwrap();

        assert_eq!(*c, (*a) * (*b));
    }


    println!("testing multiplier...");
    let h_mult_r1_r2 = evaluator.mult(&h_r1, &h_r2).await;
    let mult_r1_r2 = evaluator.output_wire(&h_mult_r1_r2).await;
    assert_eq!(mult_r1_r2, r1 * r2);

    println!("testing batch multiplier...");
    let mut xs_handles = Vec::new();
    let mut ys_handles = Vec::new();
    for _i in 0..5 {
        let h_r1 = evaluator.ran();
        let h_r2 = evaluator.ran();

        xs_handles.push(h_r1);
        ys_handles.push(h_r2);
    }

    let xs_mult_ys_handles = evaluator.batch_mult(
        &xs_handles,
        &ys_handles
    ).await;

    for i in 0..5 {
        let x = evaluator.output_wire(&xs_handles[i]).await;
        let y = evaluator.output_wire(&ys_handles[i]).await;
        let xy = evaluator.output_wire(&xs_mult_ys_handles[i]).await;

        assert_eq!(x * y, xy);
    }


    println!("testing inverter...");
    let h_r3 = evaluator.ran();
    let r3 = evaluator.output_wire(&h_r3).await;
    let h_r3_inverted = evaluator.inv(&h_r3).await;
    let r3_inverted = evaluator.output_wire(&h_r3_inverted).await;
    assert_eq!(ark_bls12_377::Fr::from(1), r3 * r3_inverted);

    println!("testing batch inverter...");
    let xs_handles: Vec<String> = (0..5)
            .into_iter()
            .map(|_| evaluator.ran())
            .collect();
    let inv_xs_handles = evaluator.batch_inv(&xs_handles).await;
    for i in 0..5 {
        let x = evaluator.output_wire(&xs_handles[i]).await;
        let inv_x = evaluator.output_wire(&inv_xs_handles[i]).await;
        assert_eq!(ark_bls12_377::Fr::from(1), x * inv_x);
    }

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