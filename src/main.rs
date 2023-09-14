use std::{thread, collections::{HashMap, HashSet}, time::Duration, vec, ops::*};
use ark_ec::{CurveGroup, AffineRepr, pairing::Pairing};
use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, GeneralEvaluationDomain, EvaluationDomain, Polynomial};
use ark_serialize::CanonicalSerialize;
use ark_std::{Zero, One};
use async_std::task;
//use std::sync::mpsc;
use futures::channel::*;
use clap::Parser;
use num_bigint::BigUint;
use serde_json::json;

mod network;
mod evaluator;
mod address_book;
mod common;
mod utils;
mod kzg;

use address_book::*;
use evaluator::*;
use common::*;
use kzg::*;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long)]
    id: String,

    /// Fixed value to generate deterministic peer id
    #[clap(long)]
    seed: u8,
}

fn parse_addr_book_from_json() -> Pok3rAddrBook {
    let config = json!({
        "addr_book": [ //addr_book is a list of ed25519 pubkeys
            "12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X", //pubkey of node with seed 1
            "12D3KooWH3uVF6wv47WnArKHk5p6cvgCJEb74UTmxztmQDc298L3", //pubkey of node with seed 2
            "12D3KooWQYhTNQdmr3ArTeUHRYzFg94BKyTkoWBDWez9kSCVe2Xo"  //pubkey of node with seed 3
        ]
    });
    let mut peers: Vec<String> = config["addr_book"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| String::from(o.as_str().unwrap()))
        .collect();
    peers.sort();

    let mut output: Pok3rAddrBook = HashMap::new();
    let mut counter = 0;
    for peer in peers {
        let pok3rpeer = Pok3rPeer {
            peer_id: peer.to_owned(),
            node_id: counter,
        };

        output.insert(peer, pok3rpeer);
        counter += 1;
    }
    output
}

#[async_std::main]
async fn main() {
    let args = Args::parse();

    //these channels will connect the evaluator and the network daemons
    let (mut n2e_tx, n2e_rx) = mpsc::unbounded::<EvalNetMsg>();
    let (e2n_tx, e2n_rx) = mpsc::unbounded::<EvalNetMsg>();

    let netd_handle = thread::spawn(move || {
        let result = task::block_on(
            network::run_networking_daemon(
                args.seed, 
                &parse_addr_book_from_json(), 
                &mut n2e_tx,
                e2n_rx)
        );
        if let Err(err) = result {
            eprint!("Networking error {:?}", err);
        }
    });
    
    let addr_book = parse_addr_book_from_json();
    let mut mpc = Evaluator::new(&args.id, addr_book, e2n_tx, n2e_rx).await;

    //this is a hack until we figure out
    task::block_on(async {
        task::sleep(Duration::from_secs(1)).await;
        println!("After sleeping for 1 second.");
    });

    mpc.test_networking().await;
    evaluator::perform_sanity_testing(&mut mpc).await;
    let card_shares = shuffle_deck(&mut mpc).await;
    // compute_permutation_argument(&mut mpc, &card_shares).await;

    evaluator::test_sigma(&mut mpc).await;

    //eval_handle.join().unwrap();
    netd_handle.join().unwrap();
}

fn map_roots_of_unity_to_cards() -> HashMap<F, String> {
    let mut output: HashMap<F, String> = HashMap::new();
    
    // get generator for the 64 powers of 64-th root of unity
    let ω = utils::multiplicative_subgroup_of_size(64);

    // map each power to a card
    // map 52 real cards
    for i in 0..52 {
        let ω_pow_i = utils::compute_power(&ω, i as u64);
        let card_name = i.to_string();
        output.insert(ω_pow_i, card_name);
    }

    //and 12 jokers
    for i in 52..64 {
        let ω_pow_i = utils::compute_power(&ω, i as u64);
        output.insert(ω_pow_i, String::from("Joker"));
    }

    output
}

async fn shuffle_deck(evaluator: &mut Evaluator) -> (Vec<String>, Vec<F>) {
    println!("-------------- Starting Pok3r shuffle -----------------");

    //step 1: parties invoke F_RAN to obtain [sk]
    let sk = evaluator.ran();

    //stores (handle, wire value) pairs
    let mut card_share_handles = Vec::new();
    let mut card_share_values = Vec::new();
    //stores set of card prfs encountered
    let mut prfs = HashSet::new();

    while card_share_values.len() < 64 { //until you get 64 unique cards
        let h_r = evaluator.ran();
        let (h_a, h_b, h_c) = evaluator.beaver().await;

        let a_i = evaluator.ran();
        let c_i = evaluator.ran_64(&a_i).await;
        let t_i = evaluator.add(&c_i, &sk);
        let t_i = evaluator.inv(
            &t_i,
            &h_r,
            (&h_a, &h_b, &h_c)
        ).await;

        // y_i = g^{1 / (sk + w_i)}
        let y_i = evaluator.output_wire_in_exponent(&t_i).await;

        //add card if it hasnt been seen before
        if ! prfs.contains(&y_i) {
            prfs.insert(y_i.clone());
            card_share_handles.push(c_i.clone());
            card_share_values.push(evaluator.get_wire(&c_i));
        }
    }

    let card_mapping = map_roots_of_unity_to_cards();
    for h_c in &card_share_handles {
        let opened_card = evaluator.output_wire(&h_c).await;
        println!("{}", card_mapping.get(&opened_card).unwrap());
    }

    println!("-------------- Ending Pok3r shuffle -----------------");
    return (card_share_handles.clone(), card_share_values);
}

async fn compute_permutation_argument(
    evaluator: &mut Evaluator,
    card_share_handles: Vec<String>,
    card_shares: &Vec<F>
) -> PermutationProof {
    let mut r_is = vec![]; //vector of (handle, share_value) pairs
    let mut r_inv_is = vec![]; //vector of (handle, share_value) pairs

    for _i in 0..53 {
        let (h_a, h_b, h_c) = evaluator.beaver().await;
        let h_t = evaluator.ran();

        let h_r_i = evaluator.ran();
        let h_r_inv_i = evaluator.inv(
            &h_r_i,
            &h_t,
            (&h_a, &h_b, &h_c)
        ).await;

        r_is.push((h_r_i.clone(), evaluator.get_wire(&h_r_i)));
        r_inv_is.push((h_r_inv_i.clone(), evaluator.get_wire(&h_r_inv_i)));
    }

    let mut b_is = vec![]; //vector of (handle, share_value) pairs
    for i in 0..52 {
        let (h_a, h_b, h_c) = evaluator.beaver().await;

        let h_r_inv_0 = &r_inv_is.get(0).unwrap().0;
        let h_r_i_plus_1 = &r_is.get(i+1).unwrap().0;

        let h_b_i = evaluator.mult(
            h_r_inv_0,
            h_r_i_plus_1,
            (&h_a, &h_b, &h_c)
        ).await;

        b_is.push((h_b_i.clone(), evaluator.get_wire(&h_b_i)));
    }

    let f_name = String::from("f");
    let f_share = utils::interpolate_poly_over_mult_subgroup(card_shares);
    let f_share_com = utils::commit_poly(&f_share);
    let f_com = evaluator.add_g1_elements_from_all_parties(&f_share_com, &f_name).await;

    let ω = utils::multiplicative_subgroup_of_size(64);
    let v_evals: Vec<F> = (0..52)
        .into_iter()
        .map(|i| utils::compute_power(&ω, i as u64))
        .collect();
    let v = utils::interpolate_poly_over_mult_subgroup(&v_evals);
    let v_com = utils::commit_poly(&v);

    // Hash v_com and f_com to obtain randomness for batching
    let mut v_bytes = Vec::new();
    let mut f_bytes = Vec::new();

    v_com.serialize_uncompressed(&mut v_bytes).unwrap();
    f_com.serialize_uncompressed(&mut f_bytes).unwrap();

    let y1 = utils::fs_hash(vec![&v_bytes, &f_bytes], 1)[0];

    // Locally compute g(X) shares from f(X) shares
    let mut g_shares = vec![];
    let mut h_g_shares = vec![];
    for i in 0..52 {
        let f_i = f_share.coeffs[i];
        let g_i = f_i + y1;
        g_shares.push(g_i);

        h_g_shares[i] = evaluator.clear_add(&card_share_handles[i], y1);
    }

    let g_share_poly = DensePolynomial::from_coefficients_vec(g_shares.clone());

    // Commit to g(X)
    let g_share_com = utils::commit_poly(&g_share_poly);
    let g_com = evaluator.add_g1_elements_from_all_parties(&g_share_com, &String::from("g")).await;

    // Compute h(X) = v(X) + y1
    let mut h_vals = vec![];
    for i in 0..52 {
        let v_i = v.coeffs[i];
        let h_i = v_i + y1;
        h_vals.push(h_i);
    }

    // Compute s_i' and t_i'
    let mut t_prime_is = vec![];

    for i in 0..52 {
        let (h_a, h_b, h_c) = evaluator.beaver().await;

        let h_r_i = &r_is.get(i).unwrap().0;
        let h_r_inv_i_plus_1 = &r_inv_is.get(i+1).unwrap().0;
        
        // Get a handle for g_i and scale with h_i^inv
        let h_g_i = &h_g_shares[i];
        let h_h_inv_g_i = &evaluator.scale(h_g_i, h_vals[i]);

        let s_prime_i = evaluator.mult(
            h_r_i,
            h_h_inv_g_i,
            (&h_a, &h_b, &h_c)
        ).await;

        let t_prime_i = evaluator.mult(
            h_r_inv_i_plus_1,
            &s_prime_i,
            (&h_a, &h_b, &h_c)
        ).await;

        let t_prime_i = evaluator.output_wire(&t_prime_i).await;
        t_prime_is.push(t_prime_i);
    }

    // Locally compute t_i
    let mut t_is = vec![];
    for i in 0..52 {
        // let tmp = product of t'_i from 0 to i
        let mut tmp = F::one();
        for j in 0..i {
            tmp = tmp * t_prime_is[j];
        }

        let t_i = evaluator.scale(&b_is[i].0, tmp);       

        t_is.push((t_i.clone(), evaluator.get_wire(&t_i)));
    }

    // Commit to t(X)
    let t_shares : Vec<F> = t_is.clone().into_iter().map(|x| x.1).collect();
    let t_share_poly = DensePolynomial::from_coefficients_vec(t_shares.clone());
    let t_share_com = utils::commit_poly(&t_share_poly);
    let t_com = evaluator.add_g1_elements_from_all_parties(&t_share_com, &String::from("t")).await;

    // Compute d_i
    let mut d_is : Vec<F> = vec![];

    for i in 0..52 {
        let (h_a, h_b, h_c) = evaluator.beaver().await;

        // alpha_i = t_i * g_i-1
        let alpha_i = evaluator.mult(
            &t_is[i].0,
            &h_g_shares[i],
            (&h_a, &h_b, &h_c)
        ).await;

        // d_i = h_i-1 * t_i-1 - alpha_i
        let tmp = evaluator.scale(&t_is[i].0, -h_vals[i]);
        let minus_d_i = evaluator.add(&tmp, &alpha_i);

        d_is.push(- evaluator.get_wire(&minus_d_i));
    }

    // Compute share polynomials of d(X)
    let d_share_poly = DensePolynomial::<F>::from_coefficients_vec(d_is.clone());

    // Compute q(X) and r(X) as quotient and remainder of d(X) / (X^52 - 1)
    let domain = GeneralEvaluationDomain::<F>::new(52).unwrap();
    let (q_share_poly, _) = d_share_poly.divide_by_vanishing_poly(domain).unwrap();

    // Commit to q(X)
    let q_share_com = utils::commit_poly(&q_share_poly);
    let q_com = evaluator.add_g1_elements_from_all_parties(&q_share_com, &String::from("q")).await;

    // Compute y2 = hash(v_com, f_com, q_com, t_com, g_com)
    let mut v_bytes = Vec::new();
    let mut f_bytes = Vec::new();
    let mut q_bytes = Vec::new();
    let mut t_bytes = Vec::new();
    let mut g_bytes = Vec::new();

    v_com.serialize_uncompressed(&mut v_bytes).unwrap();
    f_com.serialize_uncompressed(&mut f_bytes).unwrap();
    q_com.serialize_uncompressed(&mut q_bytes).unwrap();
    t_com.serialize_uncompressed(&mut t_bytes).unwrap();
    g_com.serialize_uncompressed(&mut g_bytes).unwrap();

    let y2 = utils::fs_hash(vec![&v_bytes, &f_bytes, &q_bytes, &t_bytes, &g_bytes], 1)[0];

    let w = utils::multiplicative_subgroup_of_size(64);
    let w51 = utils::compute_power(&w, 51);

    // Evaluate t(x) at w^51
    let h_y1 = evaluator.share_poly_eval(t_share_poly.clone(), w51).await;
    let pi_1 = evaluator.eval_proof_with_share_poly(t_share_poly.clone(), w51).await;

    // Evaluate t(x) at y2
    let h_y2 = evaluator.share_poly_eval(t_share_poly.clone(), y2).await;
    let pi_2 = evaluator.eval_proof_with_share_poly(t_share_poly.clone(), y2).await;

    // Evaluate t(x) at w * y2
    let h_y3 = evaluator.share_poly_eval(t_share_poly.clone(), w * y2).await;
    let pi_3 = evaluator.eval_proof_with_share_poly(t_share_poly.clone(), w * y2).await;

    // Evaluate g(x) at w * y2
    let h_y4 = evaluator.share_poly_eval(g_share_poly.clone(), w * y2).await;
    let pi_4 = evaluator.eval_proof_with_share_poly(g_share_poly.clone(), w * y2).await;

    // Evaluate q(x) at y2
    let h_y5 = evaluator.share_poly_eval(q_share_poly.clone(), y2).await;
    let pi_5 = evaluator.eval_proof_with_share_poly(q_share_poly.clone(), y2).await;

    PermutationProof {
        y1: evaluator.get_wire(&h_y1),
        y2: evaluator.get_wire(&h_y2),
        y3: evaluator.get_wire(&h_y3),
        y4: evaluator.get_wire(&h_y4),
        y5: evaluator.get_wire(&h_y5),
        pi_1,
        pi_2,
        pi_3,
        pi_4,
        pi_5,
        f_com,
        q_com,
        t_com
    }
}

async fn verify_permutation_argument(
    perm_proof: &PermutationProof,
) -> bool {
    let mut b = true;

    // Compute v(X) from powers of w
    let w = utils::multiplicative_subgroup_of_size(64);
    let w51 = utils::compute_power(&w, 51);

    let v_evals: Vec<F> = (0..52)
        .into_iter()
        .map(|i| utils::compute_power(&w, i as u64))
        .collect();

    let v = utils::interpolate_poly_over_mult_subgroup(&v_evals);
    let v_com = utils::commit_poly(&v);

    // Compute hash1 and hash2
    let mut v_bytes = Vec::new();
    let mut f_bytes = Vec::new();
    let mut q_bytes = Vec::new();
    let mut t_bytes = Vec::new();
    let mut g_bytes = Vec::new();

    v_com.serialize_uncompressed(&mut v_bytes).unwrap();
    perm_proof.f_com.serialize_uncompressed(&mut f_bytes).unwrap();

    let hash1 = utils::fs_hash(vec![&v_bytes, &f_bytes], 1)[0];

    // Compute g_com from f_com
    let g_com = (perm_proof.f_com.clone() + G1::generator().mul(hash1)).into_affine();

    perm_proof.q_com.serialize_uncompressed(&mut q_bytes).unwrap();
    perm_proof.t_com.serialize_uncompressed(&mut t_bytes).unwrap();
    g_com.serialize_uncompressed(&mut g_bytes).unwrap();

    let hash2 = utils::fs_hash(vec![&v_bytes, &f_bytes, &q_bytes, &t_bytes, &g_bytes], 1)[0];
    
    // Check all evaluation proofs
    b = b && utils::kzg_check(
        &perm_proof.t_com,
        &w51,
        &perm_proof.y1,
        &perm_proof.pi_1
    );

    b = b && utils::kzg_check(
        &perm_proof.t_com,
        &hash2,
        &perm_proof.y2,
        &perm_proof.pi_2
    );

    b = b && utils::kzg_check(
        &perm_proof.t_com,
        &(w * hash2),
        &perm_proof.y3,
        &perm_proof.pi_3
    );

    b = b && utils::kzg_check(
        &g_com,
        &(w * hash2),
        &perm_proof.y4,
        &perm_proof.pi_4
    );

    b = b && utils::kzg_check(
        &perm_proof.q_com,
        &hash2,
        &perm_proof.y5,
        &perm_proof.pi_5
    );

    // Check 1 : y3 * (v(w*hash2) + hash1) - y2 * y4 = y5 * (hash2^k - 1)
    let tmp1 = perm_proof.y3 * (v.evaluate(& (w * &hash2)) + hash1);
    let tmp2 = perm_proof.y2 * perm_proof.y4;
    let tmp3 = perm_proof.y5 * (hash2.pow([52]) - F::one());

    b = b && (tmp1 - tmp2 == tmp3);

    // Check 2 : y1 = 1
    b = b && (perm_proof.y1 == F::one());
    
    b
}

async fn encrypt_and_prove<'a>(
    evaluator: &'a mut Evaluator,
    card_handles: Vec<&'a String>,
    card_commitment: G1,
    pk: &'a G2,
    ids: Vec<&'a [u8]>
) -> EncryptProof<'a> {
    // Get all cards from card handles
    let mut cards = vec![];
    for h in card_handles.clone() {
        cards.push(evaluator.output_wire(h).await);
    }

    // Sample common randomness for encryption
    let r = evaluator.ran();

    let mut z_is = vec![]; //vector of (handle, share_value) pairs
    let mut d_is = vec![]; //vector of scaled commitments 
    let mut v_is = vec![]; //vector of (handle, share_value) pairs
    let mut v_is_reconstructed = vec![]; //vector of reconstructed v_i values
    let mut pi_is = vec![]; //vector of evaluation proofs

    let mut c1_is = vec![]; //vector of ciphertexts
    let mut c2_is = vec![]; //vector of ciphertexts

    // Compute shares of plain quotient polynomial commitment
    let mut pi_plain_vec = vec![]; //vector of plain non-reconstructed evaluation proofs
    let w = utils::multiplicative_subgroup_of_size(64);

    for i in 0..52 {
        let z = utils::compute_power(&w, i);
        let pi_plain_i = evaluator.eval_proof(card_handles.clone(), z).await;
        pi_plain_vec.push(pi_plain_i);
    }
    

    for i in 0..52 {
        let (h_a, h_b, h_c) = evaluator.beaver().await;

        // Sample mask to be encrypted
        let z_i = evaluator.ran();
        z_is.push((z_i.clone(), evaluator.get_wire(&z_i)));

        // Encrypt the mask to id_i
        let (c1_i, c2_i) = 
            evaluator.dist_ibe_encrypt(&card_handles[i], &r, pk, &ids[i]).await;
        c1_is.push(c1_i);
        c2_is.push(c2_i); 

        // Compute d_i = C_i^z_i
        let d_i = 
            evaluator.exp_and_reveal_g1(vec![card_commitment], vec![z_i.clone()], &format!("{}/{}", "D_", i)).await;
        d_is.push(d_i.clone());

        // Compute v_i = z_i * card_i
        let v_i = evaluator.mult(&z_i, &card_handles[i], (&h_a, &h_b, &h_c)).await;        
        v_is.push((v_i.clone(), evaluator.get_wire(&v_i)));
        v_is_reconstructed.push(evaluator.output_wire(&v_i).await);

        // TODO: batch this
        // Evaluation proofs of d_i at \omega^i to v_i 
        // Currently computed by raising the plain eval proof shares to the power z_i and then reconstructing the group elements

        let pi_i_share = pi_plain_vec[i].clone().mul(z_is[i].1).into_affine();
        let pi_i = 
            evaluator.add_g1_elements_from_all_parties(&pi_i_share, &format!("{}/{}", "pi_", i)).await;
        pi_is.push(pi_i);

    }

    // Hash to obtain randomness for batching

    let tmp_proof = EncryptProof{
        pk: pk.clone(),
        ids: ids.clone(),
        card_commitment: card_commitment.clone(),
        masked_commitments: d_is.clone(),
        masked_evals: v_is_reconstructed.clone(),
        eval_proofs: pi_is.clone(),
        ciphertexts: c1_is.clone().into_iter().zip(c2_is.clone().into_iter()).collect(),
        sigma_proof: None,
    };

    let s = utils::fs_hash(vec![&tmp_proof.to_bytes()], 52);

    // Compute batched pairing base for sigma proof
    let mut e_batch = Gt::zero();

    for i in 0..52 {
        // TODO: fix this. Need proper hash to curve
        let x_bigint = BigUint::from_bytes_be(ids[i]);
        let x_f = F::from(x_bigint);
        let hash_id = G1::generator().mul(x_f);

        let h = <Curve as Pairing>::pairing(hash_id, pk);

        e_batch = e_batch.add(h.mul(s[i]));
    }

    let mut wit_1 = vec![];
    
    for i in 0..52 {
        wit_1.push(z_is[i].clone().0);
    }

    let proof = evaluator.dist_sigma_proof(
            &card_commitment,
            &G1::generator(),
            &e_batch,
            wit_1,
            r,
            s).await;

    EncryptProof {
        pk: pk.clone(),
        ids: ids,
        card_commitment: card_commitment,
        masked_commitments: d_is,
        masked_evals: v_is_reconstructed,
        eval_proofs: pi_is,
        ciphertexts: c1_is.into_iter().zip(c2_is.into_iter()).collect(),
        sigma_proof: Some(proof),
    }
}

async fn local_verify_encryption_proof(
    evaluator: &mut Evaluator,
    proof: &EncryptProof<'_>,
) -> bool {
    // Check that all ciphertexts share the same randomness
    let c1 = proof.ciphertexts[0].0.clone();
    for i in 1..52 {
        if proof.ciphertexts[i].0 != c1 {
            return false;
        }
    }

    // Check the sigma proof

    // Hash to obtain randomness for batching
    let s = utils::fs_hash(vec![&proof.to_bytes()], 52);

    // Compute e_batch
    let mut e_batch = Gt::zero();

    for i in 0..52 {
        let x_bigint = BigUint::from_bytes_be(proof.ids[i]);
        let x_f = F::from(x_bigint);
        let hash_id = G1::generator().mul(x_f);

        let h = <Curve as Pairing>::pairing(hash_id, &proof.pk);

        e_batch = e_batch.add(h.mul(s[i]));
    }

    // Compute d_batch
    let mut d_batch = G1::zero();

    for i in 0..52 {
        d_batch = d_batch.add(proof.masked_commitments[i].mul(s[i])).into_affine();
    }

    // Compute c2_batch
    let mut c2_batch = Gt::zero();

    for i in 0..52 {
        c2_batch = c2_batch.add(proof.ciphertexts[i].1.clone());
    }    

    // Verify sigma proof
    if evaluator.local_verify_sigma_proof(
        &proof.card_commitment, 
        &d_batch, 
        &G1::generator(), 
        &c1, 
        &e_batch, 
        &c2_batch, 
        proof.sigma_proof.as_ref().unwrap()) == false {
        return false;
    }

    true
}