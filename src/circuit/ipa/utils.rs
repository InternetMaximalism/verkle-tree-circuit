use std::io::{Error, ErrorKind};

use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::{ConstraintSystem, PrimeField, PrimeFieldRepr, SynthesisError};
use franklin_crypto::circuit::ecc::EdwardsPoint;
use franklin_crypto::circuit::num::AllocatedNum;
use franklin_crypto::jubjub::JubjubEngine;

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
        result[i] = result[i].mul(cs.namespace(|| "mul"), x)?;
        result[i] = result[i].add(cs.namespace(|| "add"), &a[i])?;
    }

    Ok(result)
}

// Computes c[i] = a[i] + b[i] * x
// returns c
// panics if len(a) != len(b)
pub fn fold_points<'a, E: JubjubEngine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    a: &[EdwardsPoint<E>],
    b: &[EdwardsPoint<E>],
    x: &AllocatedNum<E>,
    jubjub_params: &E::Params,
) -> Result<Vec<EdwardsPoint<E>>, SynthesisError> {
    if a.len() != b.len() {
        return Err(Error::new(ErrorKind::InvalidData, "slices not equal length").into());
    }

    let mut result = b.to_vec();
    for i in 0..b.len() {
        let x_bits = x.into_bits_le(cs.namespace(|| "into_bits_le"))?;
        result[i] = result[i].mul(cs.namespace(|| "mul"), &x_bits, jubjub_params)?;
        result[i] = result[i].add(cs.namespace(|| "add"), &a[i], jubjub_params)?;
    }

    Ok(result)
}

pub fn multi_scalar<'a, E: JubjubEngine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    points: &[EdwardsPoint<E>],
    scalars: &[AllocatedNum<E>],
    jubjub_params: &E::Params,
) -> Result<EdwardsPoint<E>, SynthesisError> {
    let wrapped_result_x: AllocatedNum<E> = AllocatedNum::zero(cs.namespace(|| "zero"))?;
    let wrapped_result_y: AllocatedNum<E> = AllocatedNum::zero(cs.namespace(|| "zero"))?;
    let mut wrapped_result: EdwardsPoint<E> = EdwardsPoint::interpret(
        cs.namespace(|| "wrapped_result"),
        &wrapped_result_x,
        &wrapped_result_y,
        &jubjub_params,
    )?; // E::G1Affine::one()
    for i in 0..points.len() {
        let scalar_i_bits = scalars[i].into_bits_le(cs.namespace(|| "into_bits_le"))?;
        let mut tmp = points[i].mul(
            cs.namespace(|| "multiply points_i by scalar_i"),
            &scalar_i_bits,
            jubjub_params,
        )?; // tmp = points[i] * scalars[i]
        wrapped_result = wrapped_result.add(
            cs.namespace(|| "add wrapped_result to tmp"),
            &mut tmp,
            jubjub_params,
        )?;
        // result += tmp
    }

    Ok(wrapped_result)
}

// Commits to a polynomial using the input group elements
// panics if the number of group elements does not equal the number of polynomial coefficients
pub fn commit<'a, E: JubjubEngine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    group_elements: &[EdwardsPoint<E>],
    polynomial: &[AllocatedNum<E>],
    jubjub_params: &E::Params,
) -> Result<EdwardsPoint<E>, SynthesisError> {
    if group_elements.len() != polynomial.len() {
        let error = format!(
            "diff sizes, {} != {}",
            group_elements.len(),
            polynomial.len()
        );
        return Err(Error::new(ErrorKind::InvalidData, error).into());
    }

    let result = multi_scalar::<E, CS>(cs, group_elements, polynomial, jubjub_params)?;

    Ok(result)
}
