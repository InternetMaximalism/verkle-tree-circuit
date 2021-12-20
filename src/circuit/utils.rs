use franklin_crypto::bellman::pairing::ff::{PrimeField, PrimeFieldRepr};

pub fn read_point<F: PrimeField>(reader: &mut std::io::Cursor<Vec<u8>>) -> anyhow::Result<F> {
  let mut raw_value = F::Repr::default();
  raw_value.read_le(reader)?;
  let result = F::from_repr(raw_value)?;

  Ok(result)
}

pub fn write_point<F: PrimeField>(
  writer: &mut std::io::Cursor<Vec<u8>>,
  value: F,
) -> anyhow::Result<()> {
  value.into_repr().write_le(writer)?;

  Ok(())
}
