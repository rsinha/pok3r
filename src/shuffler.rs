use std::{collections::*, vec, ops::*};
use ark_ec::{pairing::Pairing, CurveGroup, Group};
use ark_ff::Field;
use ark_poly::{ GeneralEvaluationDomain, EvaluationDomain, Polynomial, univariate::{DensePolynomial, DenseOrSparsePolynomial}, DenseUVPolynomial};
use ark_serialize::CanonicalSerialize;
use ark_std::{Zero, One, UniformRand};
use num_bigint::BigUint;
use rand::{rngs::StdRng, SeedableRng};

use crate::evaluator::*;
use crate::common::*;
use crate::utils;
use crate::kzg::*;

type KZG = crate::kzg::KZG10::<Curve, DensePolynomial<<Curve as Pairing>::ScalarField>>;

pub fn compute_params() -> UniversalParams<Curve> {
    let pp = KZG::setup(1024, &mut StdRng::from_seed([42u8; 32]));
    pp
}

pub fn compute_keyper_keys() -> (F, G2) {
    let mut seeded_rng = StdRng::from_seed([42u8; 32]);
    let msk = F::rand(&mut seeded_rng);
    let mpk = G2::generator().mul(msk);

    return (msk, mpk);
}

pub fn compute_decryption_key(card_id: &BigUint, msk: F) -> G1 {
    let hash_id = G1::generator().mul(F::from(card_id.clone()));
    let dec_key = hash_id * msk;
    dec_key
}

pub fn compute_decryption_cache() -> Vec<Gt> {
    let w = utils::multiplicative_subgroup_of_size(PERM_SIZE as u64);
    let w_powers = (0..PERM_SIZE)
        .into_iter()
        .map(|i| utils::compute_power(&w, i as u64))
        .collect::<Vec<F>>();

    let cache: Vec<Gt> = w_powers
        .iter()
        .map(|x| Gt::generator() * x)
        .collect();

    cache
}

pub async fn shuffle_deck(evaluator: &mut Evaluator) -> Vec<String> {
    //step 1: parties invoke F_RAN to obtain [sk]
    let sk = evaluator.ran();

    //stores (handle, wire value) pairs
    let mut card_share_handles = Vec::new();
    //stores set of card prfs encountered
    let mut prfs = HashSet::new();

    // Compute prfs for cards 52 to 63 and add to prfs first
    // So that the positions of these cards are fixed in the permutation

    let ω = utils::multiplicative_subgroup_of_size(PERM_SIZE as u64);
    let powers_of_ω = (0..PERM_SIZE)
        .into_iter()
        .map(|i| utils::compute_power(&ω, i as u64))
        .collect::<Vec<F>>();

    // y_i = g^{1 / (sk + w_i)}
    let denoms = (DECK_SIZE..PERM_SIZE)
        .into_iter()
        .map(|i| evaluator.clear_add(&sk, powers_of_ω[i]))
        .collect::<Vec<String>>();

    let t_is = evaluator.batch_inv(&denoms).await;

    let y_is = evaluator.batch_output_wire_in_exponent(&t_is).await;

    // first include the cards 52..63 within the prf set and return set
    for i in 0..(PERM_SIZE - DECK_SIZE) {
        prfs.insert(y_is[i].clone());
        let handle = evaluator.fixed_wire_handle(powers_of_ω[i + DECK_SIZE]);
        card_share_handles.push(handle.clone());
    }

    // collect NUM_SAMPLES worth of random cards
    let c_is = evaluator.batch_ran_64(NUM_SAMPLES).await;

    let t_is = (0..NUM_SAMPLES)
        .into_iter()
        .map(|i| evaluator.add(&c_is[i], &sk))
        .collect::<Vec<String>>();

    let t_is = evaluator.batch_inv(&t_is).await;
    let y_is = evaluator.batch_output_wire_in_exponent(&t_is).await;

    for i in 0..NUM_SAMPLES {
        //add card if it hasnt been seen before
        if ! prfs.contains(&y_is[i]) {
            prfs.insert(y_is[i].clone());
            card_share_handles.push(c_is[i].clone());
        }
    }

    // Assert that the length is 64
    assert_eq!(card_share_handles.len(), PERM_SIZE, 
        "We don't have enough cards - try again");

    return card_share_handles.clone();
}

pub async fn compute_permutation_argument(
    pp: &UniversalParams<Curve>,
    evaluator: &mut Evaluator,
    card_share_handles: &Vec<String>,
) -> (PermutationProof, String) {

    // Compute r_i and r_i^-1
    let r_is = (0..PERM_SIZE+1)
        .into_iter()
        .map(|_i| evaluator.ran())
        .collect::<Vec<String>>();

    let r_inv_is = evaluator.batch_inv(&r_is).await;

    // Compute b_i from r_i and r_i^-1; b_i = r_i / r_0 for i in 0..65
    let b_is = evaluator.batch_mult(
        &vec![r_inv_is[0].clone(); PERM_SIZE], 
        &r_is[1..PERM_SIZE+1].to_vec()
    ).await;

    // 8: Interpret the vector fi as evaluations of a polynomial f(X).
    let f_name = String::from("perm_f");
    let card_share_values = card_share_handles
        .iter()
        .map(|x| evaluator.get_wire(x))
        .collect::<Vec<F>>();
    let f_share = 
        utils::interpolate_poly_over_mult_subgroup(&card_share_values);
    let f_share_com = KZG10::commit_g1(pp, &f_share);

    // Commit to hiding polynomials [alpha1,alpha2]*(x^PERM_SIZE - 1)
    let alpha1 = evaluator.ran();
    let alpha2 = evaluator.ran();
    
    let vanishing_poly = utils::compute_vanishing_poly(PERM_SIZE);
    let alpha1_vanish_poly_share_com = KZG10::commit_g1(pp, &vanishing_poly).mul(evaluator.get_wire(&alpha1));
    let alpha2_vanish_poly_share_com = KZG10::commit_g1(pp, &vanishing_poly).mul(evaluator.get_wire(&alpha2));

    // Commit to f(X) + alpha1 * (x^PERM_SIZE - 1)
    // Note that the polynomial itself isn't being changed, just the commitment.

    let hiding_f_com = f_share_com + alpha1_vanish_poly_share_com;
    let f_com = evaluator.add_g1_elements_from_all_parties(&hiding_f_com, &f_name).await;

    // 9: Define the degree-64 polynomial v(X) such that the evaluation vector is (1, ω, . . . , ω63)
    // This polynomial is the unpermuted vector of cards 
    let ω = utils::multiplicative_subgroup_of_size(PERM_SIZE as u64);
    let v_evals: Vec<F> = (0..PERM_SIZE)
        .into_iter()
        .map(|i| utils::compute_power(&ω, i as u64))
        .collect();
    let v = utils::interpolate_poly_over_mult_subgroup(&v_evals);
    
    // Commit to v(X) which is the public polynomial
    let v_com = KZG10::commit_g1(pp, &v);

    // 12: Parties locally compute γ1 = FSHash(C,V )
    // Hash v_com and f_com to obtain randomness for batching
    let mut v_bytes = Vec::new();
    let mut f_bytes = Vec::new();

    v_com.serialize_uncompressed(&mut v_bytes).unwrap();
    f_com.serialize_uncompressed(&mut f_bytes).unwrap();

    let y1 = utils::fs_hash(vec![&v_bytes, &f_bytes], 1)[0];

    // 13: Locally compute g(X) shares from f(X) shares
    let mut g_eval_shares = vec![];
    let mut h_g_shares = vec![];
    for i in 0..PERM_SIZE {

        // Get a handle for g_i for later
        h_g_shares.push(evaluator.clear_add(&card_share_handles[i], y1));

        let g_share_i = evaluator.get_wire(&h_g_shares[i].clone());
        g_eval_shares.push(g_share_i);
    }

    let g_share_poly = 
        utils::interpolate_poly_over_mult_subgroup(&g_eval_shares.clone());

    // Commit to g(X) - the hiding variant derived from f(X): just add alpha1 * (x^PERM_SIZE - 1)
    let g_share_com = KZG10::commit_g1(pp, &g_share_poly);
    let hiding_g_com = g_share_com + alpha1_vanish_poly_share_com;
    let g_com = evaluator.add_g1_elements_from_all_parties(&hiding_g_com, &String::from("perm_g")).await;

    // 14: Compute h(X) = v(X) + y1
    let mut h_evals = vec![];
    for i in 0..PERM_SIZE {
        let h_i = v_evals[i] + y1;
        h_evals.push(h_i);
    }
    let h_poly = utils::interpolate_poly_over_mult_subgroup(&h_evals);

    // Compute s_i' and t_i'

    let h_h_inv_g_is = (0..PERM_SIZE)
        .into_iter()
        .map(|i| {
            let h_inv_i = h_evals[i].inverse().unwrap();
            let h_g_i = &h_g_shares[i];
            evaluator.scale(h_g_i, h_inv_i)
        })
        .collect::<Vec<String>>();

    let h_s_prime_is = evaluator.batch_mult(
        &r_is[0..PERM_SIZE].to_vec(), 
        &h_h_inv_g_is
    ).await;
    let h_t_prime_is = evaluator.batch_mult(
        &r_inv_is[1..PERM_SIZE+1].to_vec(), 
        &h_s_prime_is
    ).await;

    let t_prime_is = evaluator.batch_output_wire(&h_t_prime_is).await;

    // Locally compute t_i
    // 20: for i ← 0 . . . 63 do
    // 21: Parties locally compute [ti]p ← [bi]p · ∏ij=0 t′j
    // 22: end for
    let mut t_is = vec![];
    for i in 0..PERM_SIZE {
        // let tmp = product of t'_i from 0 to i
        let mut tmp = F::one();
        for j in 0..(i+1) {
            tmp = tmp * t_prime_is[j];
        }

        // Multiply by b_i to remove random masks
        let t_i = evaluator.scale(&b_is[i], tmp);       

        t_is.push((t_i.clone(), evaluator.get_wire(&t_i)));
    }

    // Commit to t(X)
    let t_shares : &Vec<F> = &t_is.clone()
        .into_iter()
        .map(|x| x.1)
        .collect();
    let t_share_poly = utils::interpolate_poly_over_mult_subgroup(&t_shares);
    let t_share_com = KZG10::commit_g1(pp, &t_share_poly);

    // Make sure t_com is hiding as well
    let hiding_t_com = t_share_com + alpha2_vanish_poly_share_com;
    let t_com = evaluator.add_g1_elements_from_all_parties(&hiding_t_com, &String::from("t")).await;

    let tx_by_omega_share_poly = utils::poly_domain_div_ω(&t_share_poly, &ω);

    // Need to show that t(X) / t(X/ω) = g(X) / h(X)
    // 24: Compute [d(X)] as [d(X)] = h(X) * [t(X)] − [g(X) * t(X/ω)]
    let h_t_share_poly = h_poly.mul(&t_share_poly);
    let g_tx_by_omega_share_poly = evaluator.share_poly_mult(
        g_share_poly.clone(), 
        tx_by_omega_share_poly.clone()
    ).await;
    
    let d_share_poly = h_t_share_poly.sub(&g_tx_by_omega_share_poly);

    // Compute q(X) and r(X) as quotient and remainder of d(X) / (X^64 - 1)
    // TOASSERT - Reconstructed r(X) should be 0
    let domain = GeneralEvaluationDomain::<F>::new(PERM_SIZE).unwrap();
    let (q_share_poly, _) = d_share_poly.divide_by_vanishing_poly(domain).unwrap();

    // Commit to q(X) - with all the extra terms from the hiding polynomials
    // q'(x) = q(x) - alpha1 * alpha2 * (x^PERM_SIZE - 1) + alpha2 * h(x) - alpha1 * t(x/w) - alpha2 * g(x)

    let q_share_com = KZG10::commit_g1(pp, &q_share_poly);
    
    // Computing alpha1 * alpha2 * (x^PERM_SIZE - 1)
    let h_alpha1_alpha2 = evaluator.mult(&alpha1, &alpha2).await;
    let alpha1_alpha2_vanish_poly_share_com = KZG10::commit_g1(pp, &vanishing_poly).mul(evaluator.get_wire(&h_alpha1_alpha2));
    
    // Computing alpha2 * h(x)
    let alpha2_h_share_poly = h_poly.mul(evaluator.get_wire(&alpha2));
    let alpha2_h_share_poly_com = KZG10::commit_g1(pp, &alpha2_h_share_poly);

    // Computing alpha1 * t(x/w)
    // First batch mult t_is with alpha1
    let h_alpha1_t_is = evaluator.batch_mult(
        &t_is.clone()
            .into_iter()
            .map(|x| x.0)
            .collect::<Vec<String>>(),
        &vec![alpha1.clone(); PERM_SIZE]
    ).await;
    
    let alpha1_t_is = h_alpha1_t_is
        .into_iter()
        .map(|handle| evaluator.get_wire(&handle))
        .collect::<Vec<F>>();

    // Then compute alpha1 * t(x/w)
    let alpha1_t_share_poly = utils::interpolate_poly_over_mult_subgroup(&alpha1_t_is);
    let alpha1_t_by_w_share_poly = utils::poly_domain_div_ω(&alpha1_t_share_poly, &ω);

    let alpha1_t_by_w_share_poly_com = KZG10::commit_g1(pp, &alpha1_t_by_w_share_poly);

    // Computing alpha2 * g(x)
    let h_alpha2_g_is = evaluator.batch_mult(
        &h_g_shares,
        &vec![alpha2.clone(); PERM_SIZE]
    ).await;

    let alpha2_g_is = h_alpha2_g_is
        .into_iter()
        .map(|handle| evaluator.get_wire(&handle))
        .collect::<Vec<F>>();

    // Compute alpha2 * g(x)
    let alpha2_g_share_poly = utils::interpolate_poly_over_mult_subgroup(&alpha2_g_is);
    let alpha2_g_share_poly_com = KZG10::commit_g1(pp, &alpha2_g_share_poly);

    let hiding_q_share_com = 
        q_share_com
        + alpha2_h_share_poly_com        
        - alpha1_alpha2_vanish_poly_share_com
        - alpha1_t_by_w_share_poly_com
        - alpha2_g_share_poly_com;

    let q_com = evaluator.add_g1_elements_from_all_parties(&hiding_q_share_com, &String::from("perm_q")).await;

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

    // Compute polyevals and proofs
    let w = utils::multiplicative_subgroup_of_size(PERM_SIZE as u64);
    let w63 = utils::compute_power(&w, PERM_SIZE as u64 - 1);

    // Evaluate t(x) at w^63
    let h_y1 = evaluator.share_poly_eval(&t_share_poly, w63);
    // No adjustment from hiding term
    // let h_hiding_y1 = evaluator.scale(&alpha2, vanishing_poly.evaluate(&w63));
    // let h_y1 = evaluator.add(&h_y1, &h_hiding_y1);
    
    // Evaluate t(x) at y2
    let h_y2_orig = evaluator.share_poly_eval(&t_share_poly, y2);
    // Adjustment from hiding term
    let h_hiding_y2 = evaluator.scale(&alpha2, vanishing_poly.evaluate(&y2));
    let h_y2 = evaluator.add(&h_y2_orig, &h_hiding_y2);
    
    // Evaluate t(x) at y2 / w
    let h_y3_orig = evaluator.share_poly_eval(&t_share_poly, y2 / w);
    // Adjustment from hiding term
    let h_hiding_y3 = evaluator.scale(&alpha2, vanishing_poly.evaluate(&(y2 / w)));
    let h_y3 = evaluator.add(&h_y3_orig, &h_hiding_y3);
    
    // Evaluate g(x) at y2
    let h_y4_orig = evaluator.share_poly_eval(&g_share_poly, y2);
    // Adjustment from hiding term
    let h_hiding_y4 = evaluator.scale(&alpha1, vanishing_poly.evaluate(&y2));
    let h_y4 = evaluator.add(&h_y4_orig, &h_hiding_y4);
    
    // Evaluate q(x) at y2
    let h_y5_orig = evaluator.share_poly_eval(&q_share_poly, y2);
    // Adjustments from hiding terms
    let h_hiding_y5_1 = evaluator.scale(&h_alpha1_alpha2, vanishing_poly.evaluate(&y2));
    let h_hiding_y5_2 = evaluator.share_poly_eval(&alpha2_h_share_poly, y2);
    let h_hiding_y5_3 = evaluator.share_poly_eval(&alpha1_t_by_w_share_poly, y2);
    let h_hiding_y5_4 = evaluator.share_poly_eval(&alpha2_g_share_poly, y2);

    let temp1 = evaluator.add(&h_hiding_y5_3, &h_hiding_y5_4);
    let temp2 = evaluator.sub(&h_y5_orig, &temp1);
    let temp3 = evaluator.add(&temp2, &h_hiding_y5_2);
    let h_y5 = evaluator.sub(&temp3, &h_hiding_y5_1);
    
    // Compute proofs
    let pi_s = evaluator.batch_eval_proof_with_share_poly(
        pp, 
        &vec![t_share_poly.clone(), t_share_poly.clone(), t_share_poly.clone(), g_share_poly.clone(), q_share_poly.clone()],
        &vec![w63, y2, y2 / w, y2, y2]
    ).await;

    // Adjustments to proofs from hiding terms
    // pi_1
    let mut divisor = 
        DensePolynomial::from_coefficients_vec(vec![-w63, F::from(1)]);
    let (mut quotient, _) = 
        DenseOrSparsePolynomial::divide_with_q_and_r(
            &(&vanishing_poly).into(),
            &(&divisor).into(),
        ).unwrap();

    let pi_poly = KZG10::commit_g1(pp, &quotient);
    let pi_1 = pi_s[0].clone() + pi_poly.mul(evaluator.get_wire(&alpha2));

    // pi_2
    divisor = 
        DensePolynomial::from_coefficients_vec(vec![-y2, F::from(1)]);
    (quotient, _) = 
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&vanishing_poly).into(),
                &(&divisor).into(),
            ).unwrap();
    
    let pi_poly = KZG10::commit_g1(pp, &quotient);
    let pi_2 = pi_s[1].clone() + pi_poly.mul(evaluator.get_wire(&alpha2));

    // pi_3
    divisor = 
        DensePolynomial::from_coefficients_vec(vec![-(y2 / w), F::from(1)]);
    (quotient, _) = 
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&vanishing_poly).into(),
                &(&divisor).into(),
            ).unwrap();
        
    let pi_poly = KZG10::commit_g1(pp, &quotient);
    let pi_3 = pi_s[2].clone() + pi_poly.mul(evaluator.get_wire(&alpha2));

    // pi_4
    divisor = 
        DensePolynomial::from_coefficients_vec(vec![-y2, F::from(1)]);
    (quotient, _) = 
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&vanishing_poly).into(),
                &(&divisor).into(),
            ).unwrap();

    let pi_poly = KZG10::commit_g1(pp, &quotient);
    let pi_4 = pi_s[3].clone() + pi_poly.mul(evaluator.get_wire(&alpha1));

    // pi_5
    divisor = 
        DensePolynomial::from_coefficients_vec(vec![-y2, F::from(1)]);
    let (quotient_1, _) = 
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&vanishing_poly).into(),
                &(&divisor).into(),
            ).unwrap();
    
    let pi_poly_1 = KZG10::commit_g1(pp, &quotient_1);
    let mut pi_5 = pi_s[4].clone() - pi_poly_1.mul(evaluator.get_wire(&h_alpha1_alpha2));

    let (quotient_2, _) = 
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&alpha2_h_share_poly).into(),
                &(&divisor).into(),
            ).unwrap();

    let pi_poly_2 = KZG10::commit_g1(pp, &quotient_2);
    pi_5 = pi_5 + pi_poly_2;

    let (quotient_3, _) = 
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&alpha1_t_by_w_share_poly).into(),
                &(&divisor).into(),
            ).unwrap();
    
    let pi_poly_3 = KZG10::commit_g1(pp, &quotient_3);
    pi_5 = pi_5 - pi_poly_3;

    let (quotient_4, _) = 
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&alpha2_g_share_poly).into(),
                &(&divisor).into(),
            ).unwrap();

    let pi_poly_4 = KZG10::commit_g1(pp, &quotient_4);
    pi_5 = pi_5 - pi_poly_4;

    let pi_is = evaluator.batch_add_g1_elements_from_all_parties(
        &vec![pi_1, pi_2, pi_3, pi_4, pi_5],
        &vec![String::from("pi_1"), String::from("pi_2"), String::from("pi_3"), String::from("pi_4"), String::from("pi_5")]
    ).await;

    let permutation_argument = PermutationProof {
        y1: evaluator.output_wire(&h_y1).await,
        y2: evaluator.output_wire(&h_y2).await,
        y3: evaluator.output_wire(&h_y3).await,
        y4: evaluator.output_wire(&h_y4).await,
        y5: evaluator.output_wire(&h_y5).await,
        pi_1: pi_is[0].clone(),
        pi_2: pi_is[1].clone(),
        pi_3: pi_is[2].clone(),
        pi_4: pi_is[3].clone(),
        pi_5: pi_is[4].clone(),
        f_com,
        q_com,
        t_com
    };

    (permutation_argument, alpha1)
}

pub fn verify_permutation_argument(
    pp: &UniversalParams<Curve>,
    perm_proof: &PermutationProof,
) -> bool {
    let mut b = true;

    // Compute v(X) from powers of w
    let w = utils::multiplicative_subgroup_of_size(PERM_SIZE as u64);
    let w63 = utils::compute_power(&w, PERM_SIZE as u64 - 1);

    let v_evals: Vec<F> = (0..PERM_SIZE)
        .into_iter()
        .map(|i| utils::compute_power(&w, i as u64))
        .collect();

    let v = utils::interpolate_poly_over_mult_subgroup(&v_evals);
    let v_com = KZG10::commit_g1(pp, &v);

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
    let const_y1 = DensePolynomial::from_coefficients_vec(vec![hash1]);
    let const_com_y1 = KZG10::commit_g1(pp, &const_y1);

    let g_com = perm_proof.f_com.clone() + const_com_y1;

    perm_proof.q_com.serialize_uncompressed(&mut q_bytes).unwrap();
    perm_proof.t_com.serialize_uncompressed(&mut t_bytes).unwrap();
    g_com.serialize_uncompressed(&mut g_bytes).unwrap();

    let hash2 = utils::fs_hash(vec![&v_bytes, &f_bytes, &q_bytes, &t_bytes, &g_bytes], 1)[0];
    
    // Check all evaluation proofs
    b = b & KZG::verify_opening_proof(
        pp,
        &perm_proof.t_com.into_affine(),
        &w63,
        &perm_proof.y1,
        &perm_proof.pi_1.into_affine()
    );

    b = b & KZG::verify_opening_proof(
        pp,
        &perm_proof.t_com.into_affine(),
        &hash2,
        &perm_proof.y2,
        &perm_proof.pi_2.into_affine()
    );

    b = b & KZG::verify_opening_proof(
        pp,
        &perm_proof.t_com.into_affine(),
        &(hash2 / w),
        &perm_proof.y3,
        &perm_proof.pi_3.into_affine()
    );

    b = b & KZG::verify_opening_proof(
        pp,
        &g_com.into_affine(),
        &(hash2),
        &perm_proof.y4,
        &perm_proof.pi_4.into_affine()
    );

    b = b & KZG::verify_opening_proof(
        pp,
        &perm_proof.q_com.into_affine(),
        &hash2,
        &perm_proof.y5,
        &perm_proof.pi_5.into_affine()
    );

    // Check 0 : b = 1
    if ! b {
        println!("VerifyPerm - Check 0 failed");
    }

    // y1 = t(w^63)
    // y2 = t(hash2)
    // y3 = t(hash2 / w)
    // y4 = g(hash2)
    // y5 = q(hash2)
    // Check 1 : y2 * (v(hash2) + hash1) - y3 * y4 = y5 * (hash2^k - 1)
    let tmp1 = perm_proof.y2 * (v.evaluate(&hash2) + hash1);
    let tmp2 = perm_proof.y3 * perm_proof.y4;
    let tmp3 = perm_proof.y5 * (hash2.pow([PERM_SIZE as u64]) - F::one());

    b = b & (tmp1 - tmp2 == tmp3);

    if tmp1 - tmp2 != tmp3 {
        println!("VerifyPerm - Check 1 failed");
    }

    // Check 2 : y1 = 1
    b = b & (perm_proof.y1 == F::one());

    if perm_proof.y1 != F::one() {
        println!("VerifyPerm - Check 2 failed");
    }
    
    b
}


/// Produces ciphertexts and links the card commitment to the ciphertexts
pub async fn encrypt_and_prove(
    pp: &UniversalParams<Curve>,
    evaluator: &mut Evaluator,
    card_handles: Vec<String>,
    card_commitment: G1, // C = g^{\sum_i card_handles_i L_i(x) + alpha1 * (x^PERM_SIZE - 1)}
    alpha1: String,
    pk: G2,
    ids: Vec<BigUint>
) -> (Ciphertext, EncryptionProof) {
    // Get all cards from card handles
    let mut cards = vec![];
    for h in card_handles.clone() {
        cards.push(evaluator.get_wire(&h));
    }

    // Sample common randomness for encryption
    let r = evaluator.ran();

    // Encrypt the cards to ids with the same pk
    let (c1, c2s) = evaluator.batch_dist_ibe_encrypt_with_common_mask(
        &card_handles, 
        &r, 
        &pk, 
        ids.as_slice()
    ).await;

    // Encrypt an extra "card" with alpha1
    // This id can be anything (different from the others), it will never be opened.
    let (_, alpha1_c2) = evaluator.dist_ibe_encrypt(
        &alpha1, 
        &r, 
        &pk, 
        BigUint::from(123 as u64)
    ).await; 

    // Hash all the encryptions to get randomness for batching
    let mut bytes = Vec::new();
    let mut c1_bytes = Vec::new();
    let mut c2_bytes = Vec::new();

    c1.serialize_uncompressed(&mut c1_bytes).unwrap();
    bytes.extend_from_slice(&c1_bytes);

    for i in 0..PERM_SIZE {
        c2s[i].serialize_uncompressed(&mut c2_bytes).unwrap();
        bytes.extend_from_slice(&c2_bytes);
    }

    // Add alpha1 ciphertext to the hash
    alpha1_c2.serialize_uncompressed(&mut c2_bytes).unwrap();
    bytes.extend_from_slice(&c2_bytes);

    // define delta
    let delta = utils::fs_hash(vec![&bytes], 1)[0];

    // Evaluate the card commitment at delta and produce opening proof
    // Modified to take into account the hiding term
    let card_poly = utils::interpolate_poly_over_mult_subgroup(&cards);
    let vanishing_poly = utils::compute_vanishing_poly(PERM_SIZE as usize);

    // Evaluate polynomial at delta, taking into account the hiding term
    let h_poly_eval_orig = evaluator.share_poly_eval(&card_poly, delta);
    let h_hiding = evaluator.scale(&alpha1, vanishing_poly.evaluate(&delta));

    let h_poly_eval = evaluator.add(&h_poly_eval_orig, &h_hiding);
    let poly_eval = evaluator.output_wire(&h_poly_eval).await;
    
    // Produce opening proof - share
    let pi_orig = evaluator.eval_proof_with_share_poly(
        pp, 
        card_poly, 
        delta
    ).await;

    // divisor(x) = x - delta for the KZG opening proof
    let divisor = 
        DensePolynomial::from_coefficients_vec(vec![-delta, F::from(1)]);
    let (quotient, _) = 
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&vanishing_poly).into(),
                &(&divisor).into(),
            ).unwrap();

    let pi_poly = KZG10::commit_g1(pp, &quotient);
    let pi_share = pi_orig.clone() + pi_poly.mul(evaluator.get_wire(&alpha1)); 

    // reconstruct the quotient polynomial
    let pi = evaluator.add_g1_elements_from_all_parties(&pi_share, &String::from("new_enc_prove_pi")).await;

    // Batch the pairing bases
    // Evaluate lagrange basis at delta
    let mut lagrange_delta = Vec::new();
    for i in 0..PERM_SIZE {
        lagrange_delta.push(utils::compute_lagrange_basis(i as u64, PERM_SIZE as u64).evaluate(&delta));
    }

    // Computing E = prod_i e_i^Li(delta)
    let mut batch_h = G1::zero();
    for i in 0..PERM_SIZE {
        // TODO: fix this. Need proper hash to curve
        let x_f = F::from(ids[i].clone());
        let hash_id = G1::generator().mul(x_f);
        batch_h = batch_h.add(hash_id.mul(lagrange_delta[i]));
    }
    // Add the contribution from the hiding term (multiplied with (delta^PERM_SIZE - 1))
    let x_f = F::from(BigUint::from(123 as u64));
    let hash_id = G1::generator().mul(x_f);
    batch_h = batch_h.add(hash_id.mul(utils::compute_power(&delta, PERM_SIZE as u64) - F::from(1)));

    let e_batch = <Curve as Pairing>::pairing(batch_h, pk);

    // Compute t = e_batch^r
    let t = evaluator.exp_and_reveal_gt(
        vec![e_batch], 
        vec![r.clone()], 
        &String::from("new_enc_prove_t")
    ).await;

    // Sigma protocol to show that t = e_batch^r and c1 = g^r
    // Message 1
    // a1 = g^z
    // a2 = e_batch^z

    let z = evaluator.ran();
    let a1 = evaluator.exp_and_reveal_g2(
        vec![G2::generator()], 
        vec![z.clone()], 
        &String::from("new_enc_prove_a1")
    ).await;
    let a2 = evaluator.exp_and_reveal_gt(
        vec![e_batch], 
        vec![z.clone()], 
        &String::from("new_enc_prove_a2")
    ).await;

    // Message 2 - FS Hash of a1,a2
    let (mut a1_bytes, mut a2_bytes): (Vec<u8>, Vec<u8>) 
        = (Vec::new(),Vec::new());
    
    a1.serialize_uncompressed(&mut a1_bytes).unwrap();
    a2.serialize_uncompressed(&mut a2_bytes).unwrap();

    let eta = utils::fs_hash(vec![&a1_bytes, &a2_bytes], 1);

    // Message 3
    let mut h_y = evaluator.scale(&r, eta[0]);
    h_y = evaluator.add(&h_y, &z);
    let y = evaluator.output_wire(&h_y).await;

    let sigma_proof = SigmaProof{
        a1: a1,
        a2: a2,
        y: y
    };

    let encryption_proof = EncryptionProof{
        pk: pk,
        ids: ids,
        card_commitment: card_commitment,
        card_poly_eval: poly_eval,
        eval_proof: pi,
        hiding_ciphertext: alpha1_c2,
        t: t,
        sigma_proof: Some(sigma_proof)
    };

    let ctxt = (c1, c2s);

    (ctxt, encryption_proof)
}

pub fn verify_encryption_argument(
    pp: &UniversalParams<Curve>,
    ctxt: &Ciphertext,
    proof: &EncryptionProof,
) -> bool {
    // Common first element of all ciphertexts
    let c1 = ctxt.0.clone();

    // Compute delta
    let mut bytes = Vec::new();
    let mut c1_bytes = Vec::new();
    let mut c2_bytes = Vec::new();

    c1.serialize_uncompressed(&mut c1_bytes).unwrap();
    bytes.extend_from_slice(&c1_bytes);

    for i in 0..PERM_SIZE {
        ctxt.1[i].serialize_uncompressed(&mut c2_bytes).unwrap();
        bytes.extend_from_slice(&c2_bytes);
    }

    // Add alpha1 ciphertext to the hash
    proof.hiding_ciphertext.serialize_uncompressed(&mut c2_bytes).unwrap();
    bytes.extend_from_slice(&c2_bytes);

    let delta = utils::fs_hash(vec![&bytes], 1)[0];

    // Check evaluation proof
    if ! KZG::verify_opening_proof(
        pp,
        &proof.card_commitment.into_affine(),
        &delta,
        &proof.card_poly_eval,
        &proof.eval_proof.into_affine()
    ) {
        return false;
    }

    // Compute e_batch
    let mut lagrange_delta = Vec::new();
    for i in 0..PERM_SIZE {
        lagrange_delta.push(utils::compute_lagrange_basis(i as u64, PERM_SIZE as u64).evaluate(&delta));
    }

    let mut batch_h = G1::zero();
    for i in 0..PERM_SIZE {
        // TODO: fix this. Need proper hash to curve
        let x_f = F::from(proof.ids[i].clone());
        let hash_id = G1::generator().mul(x_f);
        batch_h = batch_h.add(hash_id.mul(lagrange_delta[i]));
    }
    // Add the contribution from the hiding term (multiplied with (delta^PERM_SIZE - 1))
    let x_f = F::from(BigUint::from(123 as u64));
    let hash_id = G1::generator().mul(x_f);
    batch_h = batch_h.add(hash_id.mul(utils::compute_power(&delta, PERM_SIZE as u64) - F::from(1)));

    let e_batch = <Curve as Pairing>::pairing(batch_h, proof.pk);

    // Check that prod_i c2_i^Li(delta) * alpha1_c2*(delta*PERM_SIZE - 1) = g^f(delta) * t
    let mut lhs = Gt::zero();
    for i in 0..PERM_SIZE {
        lhs = lhs + ctxt.1[i].mul(lagrange_delta[i]);
    }
    lhs = lhs + proof.hiding_ciphertext.mul(utils::compute_power(&delta, PERM_SIZE as u64) - F::from(1));

    let mut rhs = Gt::generator().mul(proof.card_poly_eval);
    rhs = rhs.add(proof.t);

    if ! lhs.eq(&rhs) {
        return false;
    }

    // Check sigma proof
    // Compute hash to get eta
    let (mut a1_bytes, mut a2_bytes): (Vec<u8>, Vec<u8>) 
        = (Vec::new(),Vec::new());

    proof.sigma_proof.as_ref().unwrap().a1.serialize_uncompressed(&mut a1_bytes).unwrap();
    proof.sigma_proof.as_ref().unwrap().a2.serialize_uncompressed(&mut a2_bytes).unwrap();

    let eta = utils::fs_hash(vec![&a1_bytes, &a2_bytes], 1);

    // Check statement 1
    let lhs = G2::generator().mul(proof.sigma_proof.as_ref().unwrap().y);
    let rhs = c1.mul(eta[0]).add(proof.sigma_proof.as_ref().unwrap().a1);

    if ! lhs.eq(&rhs) {
        return false;
    }

    // Check statement 2
    let lhs = e_batch.mul(proof.sigma_proof.as_ref().unwrap().y);
    let rhs = proof.t.mul(eta[0]).add(proof.sigma_proof.as_ref().unwrap().a2);

    if ! lhs.eq(&rhs) {
        return false;
    }

    true
}

/// Estimating time to decrypt one card at game time
pub fn decrypt_one_card(
    index: usize,
    decryption_key: &G1, // Should be sk * H(id)
    ctxt: &Ciphertext,
    cache: &[Gt],
) -> Option<usize> {
    let ciphertext = (ctxt.0, ctxt.1[index].clone());

    // IBE decryption to get g^mask
    let (c1, c2) = ciphertext;
    let div = <Curve>::pairing(decryption_key, c1);

    let exp_mask = c2.sub(div);

    for i in 0..cache.len() {
        if exp_mask.eq(&cache[i]) {
            return Some(i);
        }
    }

    return None;
}

