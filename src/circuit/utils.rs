use std::fs::OpenOptions;
use std::path::Path;

use franklin_crypto::bellman::kate_commitment::{Crs, CrsForMonomialForm};
use franklin_crypto::bellman::pairing::ff::{PrimeField, PrimeFieldRepr};
use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::worker::Worker;

pub fn read_point_le<F: PrimeField>(reader: &mut std::io::Cursor<Vec<u8>>) -> anyhow::Result<F> {
  let mut raw_value = F::Repr::default();
  raw_value.read_le(reader)?;
  let result = F::from_repr(raw_value)?;

  Ok(result)
}

pub fn read_point_be<F: PrimeField>(reader: &mut std::io::Cursor<Vec<u8>>) -> anyhow::Result<F> {
  let mut raw_value = F::Repr::default();
  raw_value.read_be(reader)?;
  let result = F::from_repr(raw_value)?;

  Ok(result)
}

pub fn write_point_le<F: PrimeField>(
  writer: &mut std::io::Cursor<Vec<u8>>,
  value: F,
) -> anyhow::Result<()> {
  value.into_repr().write_le(writer)?;

  Ok(())
}

pub fn write_point_be<F: PrimeField>(
  writer: &mut std::io::Cursor<Vec<u8>>,
  value: F,
) -> anyhow::Result<()> {
  value.into_repr().write_be(writer)?;

  Ok(())
}

pub fn make_crs_with_file<E: Engine>(crs_path: &Path, size: usize) -> anyhow::Result<()> {
  let worker = Worker::new();
  let crs = Crs::<E, CrsForMonomialForm>::crs_42(size, &worker); // ?
  let crs_file = OpenOptions::new().write(true).create(true).open(crs_path)?;
  crs.write(crs_file)?;

  Ok(())
}
