#![allow(dead_code)]
#![allow(unused_imports)]

use ark_ff::{Field, FftField, PrimeField};
use ark_poly::{
    Polynomial,
    univariate::DensePolynomial, 
    EvaluationDomain, 
    Radix2EvaluationDomain,
    Evaluations
};
type F = ark_bls12_377::Fr;

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