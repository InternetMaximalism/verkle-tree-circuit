use std::io::{Error, ErrorKind};

use core::result::Result;
use franklin_crypto::bellman::pairing::ff::{Field, PrimeField, PrimeFieldRepr};
use franklin_crypto::bellman::pairing::CurveProjective;
use franklin_crypto::bellman::SynthesisError;

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
pub fn fold_scalars<F: Field>(a: &[F], b: &[F], x: F) -> Result<Vec<F>, SynthesisError> {
  if a.len() != b.len() {
    return Err(Error::new(ErrorKind::InvalidData, "slices not equal length").into());
  }

  let mut result = b.to_vec();
  for i in 0..result.len() {
    result[i].mul_assign(&x);
    result[i].add_assign(&a[i]);
  }

  Ok(result)
}

// Computes c[i] = a[i] + b[i] * x
// returns c
// panics if len(a) != len(b)
pub fn fold_points<G: CurveProjective>(
  a: &[G],
  b: &[G],
  x: G::Scalar,
) -> Result<Vec<G>, SynthesisError> {
  if a.len() != b.len() {
    return Err(Error::new(ErrorKind::InvalidData, "slices not equal length").into());
  }

  let mut result = b.to_vec();
  for i in 0..b.len() {
    result[i].mul_assign(x);
    result[i].add_assign(&a[i]);
  }

  Ok(result)
}

pub fn slow_multi_scalar<G: CurveProjective>(points: &[G], scalars: &[G::Scalar]) -> G {
  let mut result = G::one();
  for i in 0..points.len() {
    let mut tmp = points[i];
    tmp.mul_assign(scalars[i]);
    result.add_assign(&tmp);
  }

  result
}

// Commits to a polynomial using the input group elements
// panics if the number of group elements does not equal the number of polynomial coefficients
pub fn commit<G: CurveProjective>(
  group_elements: &[G],
  polynomial: &[G::Scalar],
) -> Result<G, SynthesisError> {
  if group_elements.len() != polynomial.len() {
    let error = format!(
      "diff sizes, {} != {}",
      group_elements.len(),
      polynomial.len()
    );
    return Err(Error::new(ErrorKind::InvalidData, error).into());
  }

  let result = slow_multi_scalar::<G>(group_elements, polynomial);

  Ok(result)
}
