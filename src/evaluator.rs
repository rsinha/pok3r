
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
use rand::{rngs::StdRng, SeedableRng};

use crate::address_book::*;
use crate::common::*;
use crate::kzg::UniversalParams;
use crate::utils;

pub type Curve = ark_bls12_377::Bls12_377;
//type KZG = KZG10::<Curve, DensePolynomial<<Curve as Pairing>::ScalarField>>;
pub type F = ark_bls12_377::Fr;
pub type G1 = <Curve as Pairing>::G1Affine;
pub type G2 = <Curve as Pairing>::G2Affine;
pub type Gt = PairingOutput<Curve>;

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
    gate_counter: u64
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
            gate_counter: 0
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

        for i in 0..len {
            let (h_a, h_b, h_c) = self.beaver().await;

            bookkeeping_a.push(self.get_wire(&h_a));
            bookkeeping_b.push(self.get_wire(&h_b));
            bookkeeping_c.push(self.get_wire(&h_c));

            let handle_x_plus_a = self.add(&x_handles[i], &h_a);
            let handle_y_plus_b = self.add(&y_handles[i], &h_b);

            x_plus_a_handles.push(handle_x_plus_a);
            y_plus_b_handles.push(handle_y_plus_b);
        }

        let x_plus_a_reconstructed = self
            .batch_output_wire(&x_plus_a_handles)
            .await;

        let y_plus_b_reconstructed = self
            .batch_output_wire(&y_plus_b_handles)
            .await;

        let mut output: Vec<String> = vec![];
        let my_id = get_node_id_via_peer_id(&self.addr_book, &self.id).unwrap();
        for i in 0..len {
            //only one party should add the constant term
            let share_x_mul_y: F = match my_id {
                0 => {
                    x_plus_a_reconstructed[i] * y_plus_b_reconstructed[i] 
                    - x_plus_a_reconstructed[i] * bookkeeping_b[i] 
                    - y_plus_b_reconstructed[i] * bookkeeping_a[i]  
                    + bookkeeping_c[i]
                },
                _ => {
                    F::from(0)
                    - x_plus_a_reconstructed[i] * bookkeeping_b[i] 
                    - y_plus_b_reconstructed[i] * bookkeeping_a[i] 
                    + bookkeeping_c[i]
                }
            };

            let h = self.compute_fresh_wire_label();
            self.wire_shares.insert(h.clone(), share_x_mul_y);

            output.push(h.clone());
        }

        output
    }

    pub async fn fixed_wire_handle(&mut self, value: F) -> String {
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
    pub async fn share_poly_eval(&mut self, 
        f_poly_share: DensePolynomial<F>,
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

        let mut h_evals = Vec::new();
        let alpha = utils::multiplicative_subgroup_of_size(128);
        let powers_of_alpha: Vec<F> = (0..128)
            .into_iter()
            .map(|i| utils::compute_power(&alpha, i as u64))
            .collect();

        for i in 0..128 {
            let f_eval = self.share_poly_eval(f_poly_share.clone(), powers_of_alpha[i]).await;
            let g_eval = self.share_poly_eval(g_poly_share.clone(), powers_of_alpha[i]).await;

            // Compute h_evals from f_evals and g_evals using Beaver mult
            let h_eval = self.mult(
                &f_eval, 
                &g_eval
            ).await;

            h_evals.push(self.get_wire(&h_eval));
        }

        // Interpolate h_evals to get h_poly_share
        let h_poly_share = utils::interpolate_poly_over_mult_subgroup(&h_evals);

        h_poly_share
    }

    pub async fn beaver(&mut self) -> (String, String, String) {
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

        let msg = EvalNetMsg::PublishBatchValue {
            sender: self.id.clone(),
            handles: handles,
            values: values,
        };
        send_over_network!(msg, self.tx);

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
            tmp = self.mult(
                &tmp, 
                &tmp
            ).await;
        }

        let handle = self.compute_fresh_wire_label();
        self.wire_shares.insert(handle.clone(), self.get_wire(&tmp));
        handle
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

    pub async fn eval_proof_with_share_poly(&mut self, pp: &UniversalParams<Curve>, share_poly: DensePolynomial<F>, z: F, f_name: String) -> G1 {
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
            &String::from("ibe_c1_".to_owned() + msg_share_handle + mask_share_handle)
        ).await;
        
        let c2 = self.exp_and_reveal_gt(
            vec![Gt::generator(), h.clone()], 
            vec![msg_share_handle.clone(), mask_share_handle.clone()], 
            &String::from("ibe_c2".to_owned() + msg_share_handle + mask_share_handle)
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