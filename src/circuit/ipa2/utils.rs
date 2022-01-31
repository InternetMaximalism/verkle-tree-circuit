use std::io::{Error, ErrorKind};

use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use franklin_crypto::bellman::{PrimeField, PrimeFieldRepr, SynthesisError};
// use franklin_crypto::circuit::ecc::EdwardsPoint;
use franklin_crypto::plonk::circuit::allocated_num::AllocatedNum;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::aux_data::AuxData;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::WrappedAffinePoint;

use super::rns::BaseRnsParameters;
// use franklin_crypto::jubjub::JubjubEngine;

pub fn read_point_le<F: PrimeField>(bytes: &[u8]) -> anyhow::Result<F> {
  let mut padded_bytes = bytes.to_vec();
  let mut repr = F::Repr::default();
  let num_bits = F::NUM_BITS as usize;
  assert!(bytes.len() <= num_bits);
  for _ in bytes.len()..num_bits {
    padded_bytes.push(0);
  }
  repr.read_le::<&[u8]>(padded_bytes.as_ref())?;
  let value = F::from_repr(repr)?;

  Ok(value)
}

pub fn read_point_be<F: PrimeField>(bytes: &[u8]) -> anyhow::Result<F> {
  let mut padded_bytes = bytes.to_vec();
  padded_bytes.reverse();
  read_point_le(&padded_bytes)
}

pub fn write_point_le<F: PrimeField>(scalar: &F) -> Vec<u8> {
  let scalar_u64_vec = scalar.into_repr().as_ref().to_vec();
  let mut result = vec![0; scalar_u64_vec.len() * 8];
  for (bytes, tmp) in scalar_u64_vec
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

pub fn write_point_be<F: PrimeField>(scalar: &F) -> Vec<u8> {
  let mut result = write_point_le(scalar);
  result.reverse();

  result
}

// Computes c[i] = a[i] + b[i] * x
// returns c
// panics if len(a) != len(b)
pub fn fold_scalars<E: Engine, CS: ConstraintSystem<E>>(
  cs: &mut CS,
  a: &[AllocatedNum<E>],
  b: &[AllocatedNum<E>],
  x: &AllocatedNum<E>,
) -> Result<Vec<AllocatedNum<E>>, SynthesisError> {
  if a.len() != b.len() {
    return Err(Error::new(ErrorKind::InvalidData, "slices not equal length").into());
  }

  let mut result = b.to_vec();
  for i in 0..result.len() {
    result[i] = result[i].mul(cs, x)?;
    result[i] = result[i].add(cs, &a[i])?;
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
  x: &AllocatedNum<E>,
  rns_params: &'a BaseRnsParameters<E>,
  aux_data: &AD,
) -> Result<Vec<WP>, SynthesisError> {
  if a.len() != b.len() {
    return Err(Error::new(ErrorKind::InvalidData, "slices not equal length").into());
  }

  let result = b
    .iter()
    .enumerate()
    .map(|(i, v)| {
      let v = v.clone().mul(cs, x, None, rns_params, aux_data)?;
      let v = v.clone().add(cs, &mut a[i].clone(), rns_params)?;

      Ok(v)
    })
    .collect::<Result<Vec<_>, SynthesisError>>()?;

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
  rns_params: &'a BaseRnsParameters<E>,
  aux_data: &AD,
) -> Result<WP, SynthesisError> {
  let mut wrapped_result = WP::zero(&rns_params);
  for i in 0..points.len() {
    let mut tmp = points[i]
      .clone()
      .mul(cs, &scalars[i], None, rns_params, aux_data)?; // tmp = points[i] * scalars[i]
    wrapped_result = wrapped_result.add(cs, &mut tmp, rns_params)?; // result += tmp
  }

  Ok(wrapped_result)
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
  rns_params: &'a BaseRnsParameters<E>,
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

  let result = multi_scalar::<E, CS, WP, AD>(cs, group_elements, polynomial, rns_params, aux_data)?;

  Ok(result)
}
