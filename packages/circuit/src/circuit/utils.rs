use std::io::{Read, Write};

use franklin_crypto::bellman::pairing::ff::{PrimeField, PrimeFieldRepr};

pub fn read_field_element_le_from<F: PrimeField, R: Read>(reader: &mut R) -> anyhow::Result<F> {
    let mut raw_value = F::Repr::default();
    raw_value.read_le(reader)?;
    let result = F::from_repr(raw_value)?;

    Ok(result)
}

pub fn read_field_element_be_from<F: PrimeField, R: Read>(reader: &mut R) -> anyhow::Result<F> {
    let mut raw_value = F::Repr::default();
    raw_value.read_be(reader)?;
    let result = F::from_repr(raw_value)?;

    Ok(result)
}

pub fn write_field_element_le_into<F: PrimeField, W: Write>(
    value: F,
    writer: &mut W,
) -> Result<(), std::io::Error> {
    value.into_repr().write_le(writer)?;

    Ok(())
}

pub fn write_field_element_be_into<F: PrimeField, W: Write>(
    value: F,
    writer: &mut W,
) -> Result<(), std::io::Error> {
    value.into_repr().write_be(writer)?;

    Ok(())
}
