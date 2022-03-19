use std::io::{Error, ErrorKind};

use franklin_crypto::babyjubjub::JubjubEngine;
use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::{
    ConstraintSystem, Field, LinearCombination, PrimeField, SynthesisError,
};
use franklin_crypto::circuit::baby_ecc::EdwardsPoint;
use franklin_crypto::circuit::boolean::{field_into_allocated_bits_le_fixed, Boolean};
use franklin_crypto::circuit::num::AllocatedNum;

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

pub fn fold_scalars<E: JubjubEngine, CS: ConstraintSystem<E>>(
    _cs: &mut CS,
    a: &[Option<E::Fs>],
    b: &[Option<E::Fs>],
    x: &Option<E::Fs>,
) -> anyhow::Result<Vec<Option<E::Fs>>> {
    if a.len() != b.len() {
        anyhow::bail!(
            "two vectors must have the same lengths, {} != {}",
            a.len(),
            b.len()
        );
    }

    let mut result = b.to_vec();
    for i in 0..result.len() {
        if let (Some(r), Some(a), Some(x)) = (&mut result[i], a[i], x) {
            r.mul_assign(x);
            r.add_assign(&a);
        }
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
    x: &Option<E::Fs>,
    jubjub_params: &E::Params,
) -> Result<Vec<EdwardsPoint<E>>, SynthesisError> {
    if a.len() != b.len() {
        return Err(Error::new(ErrorKind::InvalidData, "slices not equal length").into());
    }

    let mut result = b.to_vec();
    for i in 0..b.len() {
        let x_bits = convert_bits_le(cs, *x, None)?;
        result[i] = result[i].mul(cs.namespace(|| "mul"), &x_bits, jubjub_params)?;
        result[i] = result[i].add(cs.namespace(|| "add"), &a[i], jubjub_params)?;
    }

    Ok(result)
}

pub fn multi_scalar<E: JubjubEngine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    points: &[EdwardsPoint<E>],
    scalars: &[Option<E::Fs>],
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
        let scalar_i_bits = convert_bits_le(cs, scalars[i], None)?;
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
    polynomial: &[Option<E::Fs>],
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

pub fn convert_bits_le<E, CS>(
    cs: &mut CS,
    value: Option<E::Fs>,
    bit_length: Option<usize>,
) -> Result<Vec<Boolean>, SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    let bit_length = if let Some(bit_length) = bit_length {
        assert!(bit_length <= E::Fs::NUM_BITS as usize);

        bit_length
    } else {
        E::Fs::NUM_BITS as usize
    };

    let bits = field_into_allocated_bits_le_fixed(cs, value, bit_length)?;

    // TODO
    // let mut minus_one = E::Fs::one();
    // minus_one.negate();

    // let mut packed_lc = LinearCombination::zero();
    // packed_lc.add_assign_variable_with_coeff(self, minus_one);

    // let mut coeff = E::Fs::one();

    // for bit in bits.iter() {
    //     packed_lc.add_assign_bit_with_coeff(bit, coeff);

    //     coeff.double();
    // }

    // packed_lc.enforce_zero(cs)?;

    Ok(bits.into_iter().map(|b| Boolean::from(b)).collect())
}
