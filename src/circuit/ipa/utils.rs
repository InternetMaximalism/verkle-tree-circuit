use std::io::{Error, ErrorKind};

use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::{ConstraintSystem, SynthesisError};
use franklin_crypto::circuit::ecc::EdwardsPoint;
use franklin_crypto::circuit::num::AllocatedNum;
use franklin_crypto::jubjub::JubjubEngine;

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
pub fn fold_points<E: JubjubEngine, CS: ConstraintSystem<E>>(
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

pub fn multi_scalar<E: JubjubEngine, CS: ConstraintSystem<E>>(
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
        jubjub_params,
    )?; // E::G1Affine::one()
    for i in 0..points.len() {
        let scalar_i_bits = scalars[i].into_bits_le(cs.namespace(|| "into_bits_le"))?;
        let tmp = points[i].mul(
            cs.namespace(|| "multiply points_i by scalar_i"),
            &scalar_i_bits,
            jubjub_params,
        )?; // tmp = points[i] * scalars[i]
        wrapped_result = wrapped_result.add(
            cs.namespace(|| "add wrapped_result to tmp"),
            &tmp,
            jubjub_params,
        )?;
        // result += tmp
    }

    Ok(wrapped_result)
}

// Commits to a polynomial using the input group elements
// panics if the number of group elements does not equal the number of polynomial coefficients
pub fn commit<E: JubjubEngine, CS: ConstraintSystem<E>>(
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
