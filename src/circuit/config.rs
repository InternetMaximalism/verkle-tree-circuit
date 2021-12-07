use franklin_crypto::bellman::pairing::ff::PrimeField;
use franklin_crypto::bellman::pairing::CurveProjective;

use crate::circuit::utils::from_bytes_le;

pub struct PrecomputedWeights<F: PrimeField> {
  // This stores A'(x_i) and 1/A'(x_i)
  pub barycentric_weights: Vec<F>,
  // This stores 1/k and -1/k for k \in [0, 255]
  _inverted_domain: Vec<F>,
}

const DOMAIN_SIZE: usize = 256; // common.POLY_DEGREE;

impl<F: PrimeField> PrecomputedWeights<F> {
  pub fn compute_barycentric_coefficients(&self, point: F) -> Vec<F> {
    // Compute A(x_i) * point - x_i
    let mut lagrange_evals: Vec<F> = vec![F::zero(); DOMAIN_SIZE];
    for i in 0..DOMAIN_SIZE {
      let weight = self.barycentric_weights[i];

      let i_fr = from_bytes_le::<F>(&i.to_le_bytes()).unwrap();
      lagrange_evals[i] = point;
      lagrange_evals[i].sub_assign(&i_fr);
      lagrange_evals[i].mul_assign(&weight);
    }

    let mut total_prod = F::one();
    for i in 0..DOMAIN_SIZE {
      let i_fr: F = from_bytes_le::<F>(&i.to_le_bytes()).unwrap();
      let mut tmp = point;
      tmp.sub_assign(&i_fr);
      total_prod.mul_assign(&tmp);
    }

    for i in 0..DOMAIN_SIZE {
      // TODO: there was no batch inversion API.
      // TODO: once we fully switch over to bandersnatch
      // TODO: we can switch to batch invert API

      lagrange_evals[i] = lagrange_evals[i].inverse().unwrap();
      lagrange_evals[i].mul_assign(&total_prod);
    }

    return lagrange_evals;
  }
}

pub struct IpaConfig<G: CurveProjective> {
  pub srs: Vec<G>,
  pub q: G,
  pub precomputed_weights: PrecomputedWeights<G::Scalar>,
  pub num_ipa_rounds: usize,
}
