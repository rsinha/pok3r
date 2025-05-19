use ark_poly::DenseUVPolynomial;
use ark_poly::univariate::DenseOrSparsePolynomial;
use ark_poly::univariate::DensePolynomial;
use ark_std::UniformRand;
use ark_ec::{Group, pairing::Pairing};
use ark_std::{Zero, One};
use std::collections::HashMap;
use std::ops::*;
use num_bigint::BigUint;
use rand::{rngs::StdRng, SeedableRng};

use crate::address_book::*;
use crate::common::*;
use crate::kzg::*;
use crate::network;
use crate::utils;
use crate::encoding::*;


pub struct Evaluator {
    /// local peer id
    messaging: network::MessagingSystem,
    /// stores the share associated with each wire
    wire_shares: HashMap<String, F>,
    /// keep track of gates
    gate_counter: u64,
    /// keep track of the number of beaver triples consumed
    beaver_counter: u64
}

impl Evaluator {
    pub async fn new(
        messaging: network::MessagingSystem
    ) -> Self {
        Evaluator {
            wire_shares: HashMap::new(),
            messaging,
            gate_counter: 0,
            beaver_counter: 0
        }
    }

    /// returns a unique wire label in the circuit
    fn compute_fresh_wire_label(&mut self) -> String {
        self.gate_counter += 1;
        bs58::encode(&self.gate_counter.to_be_bytes()).into_string()
    }

    /// returns the (secret-shared) wire value associated with the given handle
    pub fn get_wire(&self, handle: &String) -> F {
        self.wire_shares.get(handle).unwrap().clone()
    }

    /// asks the pre-processor to generate an additive sharing of a random value
    /// returns a string handle, which can be used to access the share in future
    pub fn ran(&mut self) -> String {
        let r = F::rand(&mut rand::thread_rng());

        let handle = self.compute_fresh_wire_label();
        self.wire_shares.insert(handle.clone(), r);
        handle
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
        let x = self.get_wire(&handle_x);
        let clear_add_share: F = match self.messaging.get_my_id() {
            0 => {x + y}
            _ => {x}
        };

        let handle_out = self.compute_fresh_wire_label();
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
        let share_x_mul_y: F = match self.messaging.get_my_id() {
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

        let mut batch_handles = vec![];
        batch_handles.extend_from_slice(&x_plus_a_handles);
        batch_handles.extend_from_slice(&y_plus_b_handles);

        let x_plus_a_and_y_plus_b = self.batch_output_wire(&batch_handles).await;

        let mut output: Vec<String> = vec![];

        for i in 0..len {
            let x_plus_a_reconstructed = x_plus_a_and_y_plus_b[i];
            let y_plus_b_reconstructed = x_plus_a_and_y_plus_b[x_plus_a_handles.len() + i];

            //only one party should add the constant term
            let share_x_mul_y: F = match self.messaging.get_my_id() {
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
        
        let share: F = match self.messaging.get_my_id() {
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

        let n: usize = self.messaging.addr_book.len();
        let my_id = get_node_id_via_peer_id(&self.messaging.addr_book, &self.messaging.id).unwrap();

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

        let n: usize = self.messaging.addr_book.len();
        let my_id = self.messaging.get_my_id();

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

    /// performs reconstruction on a wire
    pub async fn output_wire(&mut self, wire_handle: &String) -> F {
        let my_share = self.get_wire(wire_handle);

        self.messaging
            .send_to_all([wire_handle.clone()], [encode_f_as_bs58_str(&my_share)])
            .await;

        let incoming_values: Vec<F> = self.messaging
            .recv_from_all(wire_handle)
            .await
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

        // let's try to send in batches when possible
        if len > 256 {
            let mut processed_len = 0;

            while processed_len < len {
                let this_iter_len = std::cmp::min(len - processed_len, 256);
                let handles_bucket = &handles[processed_len..processed_len + this_iter_len].to_vec();
                let values_bucket = &values[processed_len..processed_len + this_iter_len].to_vec();

                self.messaging.send_to_all(handles_bucket, values_bucket).await;

                processed_len += this_iter_len;
            }
        } else {
            self.messaging.send_to_all(handles, values).await;
        }

        for i in 0..len {
            let incoming_values: Vec<F> = self.messaging
                .recv_from_all(&wire_handles[i])
                .await
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

    /// reveals the value of g^[x] for the given wire handles, and adds them up
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
        self.messaging
            .send_to_all([identifier.clone()], [encode_g1_as_bs58_str(value)])
            .await;

        let incoming_values: Vec<G1> = self.messaging
            .recv_from_all(identifier)
            .await
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
                self.messaging.send_to_all(handles_bucket.to_owned(), values_bucket.to_owned()).await;

                processed_len += this_iter_len;
            }
        }
        else {
            self.messaging.send_to_all(identifiers, values).await;
        }

        for i in 0..inputs.len() {
            let incoming_msgs = self.messaging.recv_from_all(&identifiers[i]).await;
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
        self.messaging
            .send_to_all([identifier.clone()], [encode_g2_as_bs58_str(value)])
            .await;

        let incoming_values: Vec<G2> = self.messaging
            .recv_from_all(identifier)
            .await
            .into_iter()
            .map(|x| decode_bs58_str_as_g2(&x))
            .collect();

        let mut sum: G2 = value.clone();
        for v in incoming_values { sum = sum.add(v); }
        sum
    }

    // //on input wire [x], this outputs g^[x], and reconstructs and outputs g^x
    pub async fn add_gt_elements_from_all_parties(
        &mut self, value: &Gt, 
        identifier: &String
    ) -> Gt {
        self.messaging.send_to_all([identifier.clone()], [encode_gt_as_bs58_str(value)]).await;

        let incoming_values: Vec<Gt> = self.messaging
            .recv_from_all(identifier)
            .await
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

                self.messaging.send_to_all(handles_bucket, values_bucket).await;

                processed_len += this_iter_len;
            }
        }
        else {
            self.messaging.send_to_all(identifiers, values).await;
        }

        for i in 0..inputs.len() {
            let incoming_values: Vec<Gt> = self.messaging
                .recv_from_all(&identifiers[i])
                .await
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
            sum = sum.add(base.mul(self.get_wire(exponent_handle)));
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

        assert!(len == exponent_handles.len() && len == identifiers.len());

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

        KZG::commit_g1(pp, &quotient).into()
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

            let pi_poly = KZG::commit_g1(pp, &quotient);
            pi_share_vec.push(pi_poly.into());
        }

        pi_share_vec
    }

    pub async fn dist_ibe_encrypt(
        &mut self, 
        msg_share_handle: &String, // [z1]
        mask_share_handle: &String, // [r]
        pk: &G2, 
        id: BigUint
    ) -> (G1, Gt) {
    
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

}
