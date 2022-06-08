use std::{convert::TryInto, fmt::Debug, iter::FromIterator};

use verkle_tree::ff::PrimeField;

pub fn read_field_element_le<F: PrimeField>(bytes: &[u8]) -> anyhow::Result<F> {
    let mut padded_bytes = bytes.to_vec();
    let num_bits = F::NUM_BITS as usize;
    assert!(bytes.len() <= (num_bits + 7) / 8);
    padded_bytes.resize((num_bits + 7) / 8, 0);
    padded_bytes.reverse();
    read_field_element_be(&padded_bytes)
}

pub fn read_field_element_be<F: PrimeField>(bytes: &[u8]) -> anyhow::Result<F> {
    let mut padded_bytes = bytes.to_vec();
    let num_bits = F::NUM_BITS as usize;
    assert!(bytes.len() <= (num_bits + 7) / 8);
    padded_bytes.resize((num_bits + 7) / 8, 0);

    let mut result = F::zero();
    let power = F::from(256u64);
    for value in padded_bytes.chunks(8) {
        result *= power;
        let limb: [u8; 8] = value.try_into()?;
        let limb = F::from(u64::from_be_bytes(limb));
        result += limb;
    }

    Ok(result)
}

pub fn write_field_element_le<F: PrimeField>(scalar: &F) -> Vec<u8>
where
    F::Repr: Debug,
{
    let mut result = write_field_element_be(scalar);
    result.reverse();

    // let scalar_u64_vec = scalar.to_repr().as_ref().to_vec();
    // let mut result = vec![0; scalar_u64_vec.len() * 8];
    // for (bytes, tmp) in scalar_u64_vec
    //     .iter()
    //     .map(|x| x.to_le_bytes())
    //     .zip(result.chunks_mut(8))
    // {
    //     tmp[..bytes.len()].clone_from_slice(&bytes[..]);
    // }

    result
}

pub fn write_field_element_be<F: PrimeField>(scalar: &F) -> Vec<u8>
where
    F::Repr: Debug,
{
    // let mut result = write_field_element_le(scalar);
    // result.reverse();

    let repr = format!("{:?}", scalar.to_repr());
    let result = hex::decode(&String::from_iter(repr[2..].chars())).expect("fail to parse hex");

    result
}
