use franklin_crypto::bellman::pairing::ff::PrimeField;
use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use franklin_crypto::bellman::SynthesisError;
use franklin_crypto::plonk::circuit::allocated_num::AllocatedNum;
use franklin_crypto::plonk::circuit::boolean::Boolean;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::WrappedAffinePoint;

pub const ALIGN_FIELD_ELEMENTS_TO_BITS: usize = 256;

pub fn bytes_to_keep<E: Engine>() -> usize {
    (E::Fr::CAPACITY / 8) as usize
}

fn allocated_num_to_alligned_big_endian<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    el: &AllocatedNum<E>,
) -> Result<Vec<Boolean>, SynthesisError> {
    let mut bits = el.into_bits_le(cs, None)?;

    assert!(bits.len() < ALIGN_FIELD_ELEMENTS_TO_BITS);

    bits.resize(ALIGN_FIELD_ELEMENTS_TO_BITS, Boolean::constant(false));

    bits.reverse();

    Ok(bits)
}

pub fn serialize_point_into_big_endian<
    'a,
    E: Engine,
    CS: ConstraintSystem<E>,
    WP: WrappedAffinePoint<'a, E>,
>(
    cs: &mut CS,
    point: &WP,
) -> Result<Vec<Boolean>, SynthesisError> {
    let raw_point = point.get_point();

    let x = raw_point
        .get_x()
        .force_reduce_into_field(cs)?
        .enforce_is_normalized(cs)?;
    let y = raw_point
        .get_y()
        .force_reduce_into_field(cs)?
        .enforce_is_normalized(cs)?;

    let mut serialized = vec![];

    for coord in vec![x, y].into_iter() {
        for limb in coord.into_limbs().into_iter() {
            let as_num = limb.into_variable(); // this checks coeff and constant term internally
            serialized.extend(allocated_num_to_alligned_big_endian(cs, &as_num)?);
        }
    }

    Ok(serialized)
}
