use std::io::{Error, ErrorKind};

use franklin_crypto::babyjubjub::JubjubEngine;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use franklin_crypto::bellman::{PrimeField, SynthesisError};
use franklin_crypto::plonk::circuit::allocated_num::AllocatedNum;
use franklin_crypto::plonk::circuit::bigint::field::FieldElement;

use crate::circuit::num::baby_ecc::EdwardsPoint;
use crate::circuit::num::convert_bits_le;

const FS_REPR_3_MASK: u64 = 0x03FFFFFFFFFFFFFF; // (250 - 192) bits

pub fn convert_fr_to_fs<E: JubjubEngine, CS: ConstraintSystem<E>>(
    _cs: &mut CS,
    value: &AllocatedNum<E>,
) -> anyhow::Result<Option<E::Fs>> {
    let result = if let Some(value) = value.get_value() {
        let raw_value = value.into_repr();
        let mut raw_result = <E::Fs as PrimeField>::Repr::default();
        raw_result.as_mut()[0] = raw_value.as_ref()[0];
        raw_result.as_mut()[1] = raw_value.as_ref()[1];
        raw_result.as_mut()[2] = raw_value.as_ref()[2];
        raw_result.as_mut()[3] = raw_value.as_ref()[3] & FS_REPR_3_MASK;
        let result = E::Fs::from_repr(raw_result)?;

        Some(result)
    } else {
        None
    };

    Ok(result)
}

pub fn convert_fs_to_fr<E: JubjubEngine>(value: &E::Fs) -> anyhow::Result<E::Fr> {
    let raw_value = value.into_repr();
    let mut raw_result = <E::Fr as PrimeField>::Repr::default();
    for (r, &v) in raw_result.as_mut().iter_mut().zip(raw_value.as_ref()) {
        let _ = std::mem::replace(r, v);
    }
    let result = E::Fr::from_repr(raw_result)?;

    Ok(result)
}

// Computes c[i] = a[i] + b[i] * x
// returns c
// panics if len(a) != len(b)
// pub fn fold_scalars<E: Engine, CS: ConstraintSystem<E>>(
//     cs: &mut CS,
//     a: &[AllocatedNum<E>],
//     b: &[AllocatedNum<E>],
//     x: &AllocatedNum<E>,
// ) -> Result<Vec<AllocatedNum<E>>, SynthesisError> {
//     if a.len() != b.len() {
//         return Err(Error::new(ErrorKind::InvalidData, "slices not equal length").into());
//     }

//     let mut result = b.to_vec();
//     for i in 0..result.len() {
//         result[i] = result[i].mul(cs.namespace(|| "mul"), x)?;
//         result[i] = result[i].add(cs.namespace(|| "add"), &a[i])?;
//     }

//     Ok(result)
// }

pub fn fold_scalars<'a, E: JubjubEngine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    a: &[FieldElement<'a, E, E::Fs>],
    b: &[FieldElement<'a, E, E::Fs>],
    x: &FieldElement<'a, E, E::Fs>,
) -> anyhow::Result<Vec<FieldElement<'a, E, E::Fs>>> {
    if a.len() != b.len() {
        anyhow::bail!(
            "two vectors must have the same lengths, {} != {}",
            a.len(),
            b.len()
        );
    }

    let mut result = b.to_vec();
    for (result_i, a_i) in result.iter_mut().zip(a) {
        let (tmp, _) = result_i.clone().mul(cs, x.clone())?;
        let (tmp, _) = tmp.add(cs, a_i.clone())?;

        let _ = std::mem::replace(result_i, tmp);
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
    x: &FieldElement<'a, E, E::Fs>,
    jubjub_params: &E::Params,
) -> Result<Vec<EdwardsPoint<E>>, SynthesisError> {
    if a.len() != b.len() {
        return Err(Error::new(ErrorKind::InvalidData, "slices not equal length").into());
    }

    let mut result = b.to_vec();
    for i in 0..b.len() {
        let x_bits = convert_bits_le(cs, x.clone(), Some(E::Fs::NUM_BITS as usize))?;
        result[i] = result[i].mul(cs, &x_bits, jubjub_params)?;
        result[i] = result[i].add(cs, &a[i], jubjub_params)?;
    }

    Ok(result)
}

pub fn multi_scalar<'a, E: JubjubEngine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    points: &[EdwardsPoint<E>],
    scalars: &[FieldElement<'a, E, E::Fs>],
    jubjub_params: &E::Params,
) -> Result<EdwardsPoint<E>, SynthesisError> {
    let wrapped_result_x: AllocatedNum<E> = AllocatedNum::zero(cs);
    let wrapped_result_y: AllocatedNum<E> = AllocatedNum::one(cs);
    let mut wrapped_result: EdwardsPoint<E> =
        EdwardsPoint::interpret(cs, &wrapped_result_x, &wrapped_result_y, jubjub_params)?; // infinity of Edwards curve
    for i in 0..points.len() {
        let scalar_i_bits =
            convert_bits_le(cs, scalars[i].clone(), Some(E::Fs::NUM_BITS as usize))?;
        let tmp = points[i].mul(cs, &scalar_i_bits, jubjub_params)?; // tmp = points[i] * scalars[i]
        wrapped_result = wrapped_result.add(cs, &tmp, jubjub_params)?; // result += tmp
    }

    Ok(wrapped_result)
}

// Commits to a polynomial using the input group elements
// panics if the number of group elements does not equal the number of polynomial coefficients
pub fn commit<'a, E: JubjubEngine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    group_elements: &[EdwardsPoint<E>],
    polynomial: &[FieldElement<'a, E, E::Fs>],
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
