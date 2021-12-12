use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use franklin_crypto::bellman::pairing::bn256::{Fq, FqRepr, Fr, FrRepr};
use franklin_crypto::bellman::pairing::ff::PrimeField;

// Consume 256 bits from `reader` and return an `Fq` value.
pub fn read_fq(reader: &mut std::io::Cursor<Vec<u8>>) -> anyhow::Result<Fq> {
  let mut raw_value = [0u64; 4];
  for i in 0..raw_value.len() {
    raw_value[i] = reader.read_u64::<LittleEndian>()?;
  }
  let result = Fq::from_repr(FqRepr(raw_value))?;

  Ok(result)
}

pub fn write_fq(reader: &mut std::io::Cursor<Vec<u8>>, value: Fq) -> anyhow::Result<()> {
  let raw_value: [u64; 4] = value.into_repr().0;
  for i in 0..raw_value.len() {
    reader.write_u64::<LittleEndian>(raw_value[i])?;
  }

  Ok(())
}

// Consume 256 bits from `reader` and return an `Fr` value.
pub fn read_fr(reader: &mut std::io::Cursor<Vec<u8>>) -> anyhow::Result<Fr> {
  let mut raw_value = [0u64; 4];
  for i in 0..raw_value.len() {
    raw_value[i] = reader.read_u64::<LittleEndian>()?;
  }
  let result = Fr::from_repr(FrRepr(raw_value))?;

  Ok(result)
}

pub fn write_fr(reader: &mut std::io::Cursor<Vec<u8>>, value: Fr) -> anyhow::Result<()> {
  let raw_value: [u64; 4] = value.into_repr().0;
  for i in 0..raw_value.len() {
    reader.write_u64::<LittleEndian>(raw_value[i])?;
  }

  Ok(())
}
