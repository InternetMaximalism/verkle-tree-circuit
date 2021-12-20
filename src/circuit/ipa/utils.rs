use std::io::{Error, ErrorKind};

use core::result::Result;
use franklin_crypto::bellman::pairing::ff::{PrimeField, PrimeFieldRepr};
use franklin_crypto::bellman::pairing::{CurveAffine, Engine};
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use franklin_crypto::bellman::SynthesisError;
use franklin_crypto::plonk::circuit::allocated_num::AllocatedNum;
use franklin_crypto::plonk::circuit::bigint::field::RnsParameters;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::aux_data::AuxData;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::WrappedAffinePoint;

pub fn from_bytes_le<F: PrimeField>(bytes: &[u8]) -> anyhow::Result<F> {
  let mut repr = F::Repr::default();
  repr.read_le(bytes)?;
  let value = F::from_repr(repr)?;

  Ok(value)
}

pub fn to_bytes_le<F: PrimeField>(scalar: &F) -> Vec<u8> {
  let mut result = vec![];
  for (bytes, tmp) in scalar
    .into_repr()
    .as_ref()
    .iter()
    .map(|x| x.to_le_bytes())
    .zip(result.chunks_mut(8))
  {
    for i in 0..bytes.len() {
      tmp[i] = bytes[i];
    }
  }

  result
}

// Computes c[i] = a[i] + b[i] * x
// returns c
// panics if len(a) != len(b)
pub fn fold_scalars<E: Engine, CS: ConstraintSystem<E>>(
  cs: &mut CS,
  a: &[AllocatedNum<E>],
  b: &[AllocatedNum<E>],
  x: AllocatedNum<E>,
) -> Result<Vec<AllocatedNum<E>>, SynthesisError> {
  if a.len() != b.len() {
    return Err(Error::new(ErrorKind::InvalidData, "slices not equal length").into());
  }

  let mut result = b.to_vec();
  for i in 0..result.len() {
    result[i] = result[i].mul::<CS>(cs, &x)?;
    result[i] = result[i].add::<CS>(cs, &a[i])?;
  }

  Ok(result)
}

// Computes c[i] = a[i] + b[i] * x
// returns c
// panics if len(a) != len(b)
pub fn fold_points<
  'a,
  E: Engine,
  CS: ConstraintSystem<E>,
  WP: WrappedAffinePoint<'a, E>,
  AD: AuxData<E>,
>(
  cs: &mut CS,
  a: &[WP],
  b: &[WP],
  x: AllocatedNum<E>,
  bit_limit: Option<usize>,
  rns_params: &'a RnsParameters<E, <E::G1Affine as CurveAffine>::Base>,
  aux_data: &AD,
) -> Result<Vec<WP>, SynthesisError> {
  if a.len() != b.len() {
    return Err(Error::new(ErrorKind::InvalidData, "slices not equal length").into());
  }

  let mut result = b.to_vec();
  for i in 0..b.len() {
    result[i] = result[i].mul::<CS, AD>(cs, &x, bit_limit, rns_params, aux_data)?;
    result[i] = result[i].add::<CS>(cs, &mut a[i].clone(), rns_params)?;
  }

  Ok(result)
}

pub fn multi_scalar<
  'a,
  E: Engine,
  CS: ConstraintSystem<E>,
  WP: WrappedAffinePoint<'a, E>,
  AD: AuxData<E>,
>(
  cs: &mut CS,
  points: &[WP],
  scalars: &[AllocatedNum<E>],
  bit_limit: Option<usize>,
  rns_params: &'a RnsParameters<E, <E::G1Affine as CurveAffine>::Base>,
  aux_data: &AD,
) -> Result<WP, SynthesisError> {
  let mut result = WP::alloc(cs, Some(E::G1Affine::one()), rns_params, aux_data)?;
  for i in 0..points.len() {
    let mut tmp =
      points[i]
        .clone()
        .mul::<CS, AD>(cs, &scalars[i], bit_limit, rns_params, aux_data)?; // tmp = points[i] * scalars[i]
    result = result.add::<CS>(cs, &mut tmp, rns_params)?; // result += tmp
  }

  let mut one = WP::alloc(cs, Some(E::G1Affine::one()), rns_params, aux_data)?;
  result = result.sub::<CS>(cs, &mut one, rns_params)?;

  Ok(result)
}

// Commits to a polynomial using the input group elements
// panics if the number of group elements does not equal the number of polynomial coefficients
pub fn commit<
  'a,
  E: Engine,
  CS: ConstraintSystem<E>,
  WP: WrappedAffinePoint<'a, E>,
  AD: AuxData<E>,
>(
  cs: &mut CS,
  group_elements: &[WP],
  polynomial: &[AllocatedNum<E>],
  bit_limit: Option<usize>,
  rns_params: &'a RnsParameters<E, <E::G1Affine as CurveAffine>::Base>,
  aux_data: &AD,
) -> Result<WP, SynthesisError> {
  if group_elements.len() != polynomial.len() {
    let error = format!(
      "diff sizes, {} != {}",
      group_elements.len(),
      polynomial.len()
    );
    return Err(Error::new(ErrorKind::InvalidData, error).into());
  }

  let result = multi_scalar::<E, CS, WP, AD>(
    cs,
    group_elements,
    polynomial,
    bit_limit,
    rns_params,
    aux_data,
  )?;

  Ok(result)
}
