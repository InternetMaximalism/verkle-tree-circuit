use std::io::{Error, ErrorKind};

use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use franklin_crypto::bellman::{Engine, PrimeField, SynthesisError};
use franklin_crypto::plonk::circuit::allocated_num::AllocatedNum;
// use franklin_crypto::jubjub::JubjubEngine;

use super::utils::read_point_le;

#[derive(Clone, Debug)]
pub struct PrecomputedWeights<F: PrimeField> {
  // This stores A'(x_i) and 1/A'(x_i)
  pub barycentric_weights: Vec<F>,
  // This stores 1/k and -1/k for k \in [0, 255]
  pub inverted_domain: Vec<F>,
}

pub const NUM_IPA_ROUNDS: usize = 1; // log_2(common.POLY_DEGREE);
pub const DOMAIN_SIZE: usize = 2; // common.POLY_DEGREE;

impl<F: PrimeField> PrecomputedWeights<F> {
  pub fn new() -> anyhow::Result<Self> {
    // Imagine we have two arrays of the same length and we concatenate them together
    // This is how we will store the A'(x_i) and 1/A'(x_i)
    // This midpoint variable is used to compute the offset that we need
    // to place 1/A'(x_i)

    // Note there are DOMAIN_SIZE number of weights, but we are also storing their inverses
    // so we need double the amount of space
    let mut barycentric_weights = vec![F::zero(); DOMAIN_SIZE * 2];
    for i in 0..DOMAIN_SIZE {
      let weight = PrecomputedWeights::<F>::compute_barycentric_weight_for_element(i.try_into()?)?;

      let inv_weight = weight.inverse().unwrap();

      barycentric_weights[i] = weight;
      barycentric_weights[i + DOMAIN_SIZE] = inv_weight;
    }

    // Computing 1/k and -1/k for k \in [0, 255]
    // Note that since we cannot do 1/0, we have one less element
    let midpoint = DOMAIN_SIZE - 1;
    let mut inverted_domain = vec![F::zero(); midpoint * 2];
    for i in 1usize..DOMAIN_SIZE {
      let mut k: F = F::from_repr(<F::Repr as From<u64>>::from(i.try_into()?))?;
      k = k.inverse().unwrap();

      let mut minus_k = F::zero();
      minus_k.sub_assign(&k);

      inverted_domain[i - 1] = k;
      inverted_domain[(i - 1) + midpoint] = minus_k;
    }

    Ok(Self {
      barycentric_weights,
      inverted_domain,
    })
  }

  // computes A'(x_j) where x_j must be an element in the domain
  // This is computed as the product of x_j - x_i where x_i is an element in the domain
  // and x_i is not equal to x_j
  pub fn compute_barycentric_weight_for_element(element: u64) -> anyhow::Result<F> {
    let midpoint = DOMAIN_SIZE.try_into()?;

    // let domain_element_fr = Fr::from(domain_element as u128);
    if element > midpoint {
      return Err(
        Error::new(
          ErrorKind::InvalidData,
          format!(
            "the domain is [0, {}], {} is not in the domain",
            DOMAIN_SIZE - 1,
            element
          ),
        )
        .into(),
      );
    }

    let mut total = F::one();

    for i in 0u64..midpoint {
      if i == element {
        continue;
      }

      let mut tmp = F::from_repr(<F::Repr as From<u64>>::from(element.try_into()?))?; // tmp = element
      let i_fr = F::from_repr(<F::Repr as From<u64>>::from(i.try_into()?))?;
      tmp.sub_assign(&i_fr); // tmp -= i
      total.mul_assign(&tmp); // total *= tmp
    }

    Ok(total)
  }
}

// Computes the coefficients `barycentric_coeffs` for a point `z` such that
// when we have a polynomial `p` in lagrange basis, the inner product of `p` and `barycentric_coeffs`
// is equal to p(z)
// Note that `z` should not be in the domain
// This can also be seen as the lagrange coefficients L_i(point)
pub fn compute_barycentric_coefficients<E: Engine, CS: ConstraintSystem<E>>(
  cs: &mut CS,
  precomputed_weights: &PrecomputedWeights<E::Fr>,
  point: &AllocatedNum<E>,
) -> Result<Vec<AllocatedNum<E>>, SynthesisError> {
  // Compute A(x_i) * point - x_i
  let mut lagrange_evals: Vec<AllocatedNum<E>> = Vec::with_capacity(DOMAIN_SIZE);
  for i in 0..DOMAIN_SIZE {
    let weight = AllocatedNum::alloc(cs, || Ok(precomputed_weights.barycentric_weights[i]))?;
    let wrapped_i = AllocatedNum::alloc(cs, || Ok(read_point_le(&i.to_le_bytes()).unwrap()))?;
    let mut eval = point.clone();
    eval = eval.sub(cs, &wrapped_i)?;
    eval = eval.mul(cs, &weight)?;
    lagrange_evals.push(eval);
  }

  let mut total_prod = AllocatedNum::one::<CS>(cs);
  for i in 0..DOMAIN_SIZE {
    let wrapped_i = AllocatedNum::alloc(cs, || Ok(read_point_le(&i.to_le_bytes()).unwrap()))?;
    let mut tmp = point.clone();
    tmp = tmp.sub(cs, &wrapped_i)?;
    total_prod = total_prod.mul(cs, &tmp)?;
  }

  for i in 0..DOMAIN_SIZE {
    // TODO: there was no batch inversion API.
    // TODO: once we fully switch over to bandersnatch
    // TODO: we can switch to batch invert API

    lagrange_evals[i] = lagrange_evals[i].inverse(cs)?;
    lagrange_evals[i] = lagrange_evals[i].mul(cs, &total_prod)?;
  }

  Ok(lagrange_evals)
}

#[derive(Clone)]
pub struct IpaConfig<E: Engine> {
  pub srs: Vec<E::G1Affine>,
  pub q: E::G1Affine,
  pub precomputed_weights: PrecomputedWeights<E::Fr>,
  pub num_ipa_rounds: usize,
}
