#![allow(dead_code)]
#![allow(unused_imports)]

use ark_crypto_primitives::crh::sha256::Sha256;
use rand::{rngs::StdRng, SeedableRng};
use ark_ff::{Field, FftField, PrimeField};
use ark_std::{UniformRand, test_rng, ops::*};
use ark_poly::{
    Polynomial,
    univariate::DensePolynomial, 
    EvaluationDomain, 
    Radix2EvaluationDomain,
    Evaluations
};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_serialize::*;
use ark_ec::{
    hashing::{
        curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,
    },
    short_weierstrass::{Affine, Projective},
};
use ark_ff::{
    field_hashers::{DefaultFieldHasher, HashToField},
    One, Zero,
};
use num_bigint::{BigInt, BigUint, Sign};

type Curve = ark_bls12_377::Bls12_377;
type KZG = crate::kzg::KZG10::<Curve, DensePolynomial<<Curve as Pairing>::ScalarField>>;
type F = ark_bls12_377::Fr;
type G1 = <Curve as Pairing>::G1Affine;
type G2 = <Curve as Pairing>::G2Affine;
type G1Config = ark_ec::short_weierstrass::Affine<ark_bls12_377::g1::Config>;

macro_rules! requires_power_of_2 {
    ($x:expr) => {
        assert!($x > 0 && ($x & ($x - 1)) == 0, "{} is not a power of 2", $x);
    };
}

/// returns a generator of the multiplicative subgroup of input size n
pub fn multiplicative_subgroup_of_size(n: u64) -> F {
    requires_power_of_2!(n);
    let domain = Radix2EvaluationDomain::<F>::new(n as usize).unwrap();
    domain.group_gen
}

/// interpolate polynomial which evaluates to points in v
/// the domain is the powers of n-th root of unity, where n is size of v
/// assumes n is a power of 2
pub fn interpolate_poly_over_mult_subgroup(v: &Vec<F>) -> DensePolynomial<F> {
    let n = v.len();
    let mut evals = vec![];
    for i in 0..n {
        evals.push(v[i]);
    }

    let domain = Radix2EvaluationDomain::<F>::new(n).unwrap();
    let eval_form = Evaluations::from_vec_and_domain(evals, domain);
    eval_form.interpolate()
}

pub fn commit_poly(f: &DensePolynomial<F>) -> G1 {
    // fixed seed to make sure all parties use the same KZG params
    let mut seeded_rng = StdRng::from_seed([42u8; 32]);
    let params = KZG::setup(f.degree(), &mut seeded_rng).expect("Setup failed");
    KZG::commit_g1(&params, f).unwrap()
}

pub fn compute_additive_shares(value: &F, num_shares: usize) -> Vec<F> {
    let mut sum = F::from(0);
    let mut shares = vec![];
    for _ in 1..num_shares {
        let r = F::rand(&mut rand::thread_rng());
        //let r_bs58 = bs58::encode(utils::field_to_bytes(&r)).into_string();
        shares.push(r);
        sum += r;
    }
    shares.push(value.sub(&sum));

    shares
}

pub fn compute_root(x: &F) -> F {
    x.sqrt().unwrap()
}

pub fn compute_power(x: &F, n: u64) -> F {
    x.pow([n])
}

pub fn fs_hash(x: Vec<&[u8]>, num_output: usize) -> Vec<F> {
    let hasher = <DefaultFieldHasher<Sha256> as HashToField<F>>::new(b"pok3r");
    let field_elements = hasher.hash_to_field(&x.concat(), num_output);

    field_elements
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiplicative_subgroup_of_size() {
        let n: u64 = 64;
        let ω = multiplicative_subgroup_of_size(n);
        
        //check if ω^n = 1
        let ω_pow_n_minus_1 = ω.pow([n-1]);
        let ω_pow_n = ω.pow([n]);
        let one = F::from(1);
        assert_eq!(ω_pow_n, ω_pow_n_minus_1 * ω);
        assert_eq!(one, ω_pow_n);

        //test if all other powers of ω are != 1
        for i in 1..n {
            let ω_pow_i = ω.pow([i]);
            let one = F::from(1);
            assert_ne!(ω_pow_i, one);
        }
    }
}