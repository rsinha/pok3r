use ark_poly::{Polynomial, univariate::DensePolynomial};
use ark_std::UniformRand;
use rand::Rng;

use crate::common::*;

pub fn share<R: Rng>(
    secret: &F, 
    access: (u64, u64),
    rng: &mut R
) -> Vec<(F,F)> {
    let (t, n) = access;

    // let us sample a random degree t-1 polynomial.
    // A degree t - 1 polynomial has t coefficients,
    // which we sample at random
    let mut coeffs: Vec<F> = (0..t)
        .map(|_| F::rand(rng))
        .collect();
    coeffs[0] = secret.clone();

    // we now have all the right coefficients to define the polynomial
    let poly = DensePolynomial { coeffs };

    // Shamir shares are just evaluations of our polynomial above
    let shares = (1..=n).map(|x| (F::from(x), poly.evaluate(&F::from(x)))).collect();

    shares
}


/*
 * recover implements the Shamir reconstruction algorithm,
 * where access <- (t,n) describes the access structure, and
 * shares contains the polynomial points { (x,y) }, where x is
 * some field element, and y is the polynomial evaluation at x.
 */
pub fn recover(shares: &Vec<(F,F)>) -> F {
    let xs: Vec<F> = shares.iter().map(|(x, _)| *x).collect();
    let ys: Vec<F> = shares.iter().map(|(_, y)| *y).collect();

    // compute lagrange coefficients w.r.t. x = 0.
    // we choose x = 0 because we encoded our secret at f(0)
    let lagrange_coeffs = lagrange_coefficients(&xs[..], F::from(0));

    //secret f(0) as a field element
    let secret = ys
        .iter()
        .zip(lagrange_coeffs.iter())
        .fold(F::from(0), |acc, (a,b)| acc + (a * b));
    
    secret
}

/*
 * Naive lagrange interpolation over the input x-coordinates.
 * This method computes the lagrange coefficients, which should
 * be used to compute an inner product with the y-coordinates.
 * reference: https://en.wikipedia.org/wiki/Lagrange_polynomial
*/
fn lagrange_coefficients(xs: &[F], x: F) -> Vec<F> {
    let mut output = Vec::new();

    for (i, &x_i) in xs.iter().enumerate() {
        let mut l_i = F::from(1);
        for (j, &x_j) in xs.iter().enumerate() {
            if i != j {
                l_i *= (x - x_j) / (x_i - x_j);
            }
        }
        output.push(l_i);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use rand_chacha::rand_core::SeedableRng;

    #[test]
    fn test_shamir_correctness() {
        // test if recovery on shares produces the shared secret

        //let seed: [u8; 32] = [0; 32];
        let mut rng = thread_rng();

        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

        let secret = F::rand(&mut rng);

        let shares = share(&secret, (3, 5), &mut rng);
        let recovered = recover(&shares);

        assert_eq!(secret, recovered);
    }
}