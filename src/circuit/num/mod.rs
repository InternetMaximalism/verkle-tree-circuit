pub mod baby_ecc;
pub mod lookup;

use franklin_crypto::{
    babyjubjub::{edwards, JubjubEngine},
    bellman::{
        pairing::ff::Field, plonk::better_better_cs::cs::ConstraintSystem, BitIterator, Engine,
        PrimeField, SynthesisError,
    },
    plonk::circuit::{
        allocated_num::AllocatedNum,
        bigint::{bigint::fe_to_biguint, field::FieldElement},
        boolean::{AllocatedBit, Boolean},
    },
};
use num_bigint::BigUint;
use num_traits::Zero;

use self::baby_ecc::EdwardsPoint;

pub trait SomeField<F: Field> {
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn fma(&self, to_mul: &Self, to_add: &Self) -> Self;
    fn negate(&self) -> Self;
}

impl<F: Field> SomeField<F> for Option<F> {
    fn add(&self, other: &Self) -> Self {
        match (self, other) {
            (Some(s), Some(o)) => {
                let mut tmp = *s;
                tmp.add_assign(o);

                Some(tmp)
            }
            _ => None,
        }
    }
    fn sub(&self, other: &Self) -> Self {
        match (self, other) {
            (Some(s), Some(o)) => {
                let mut tmp = *s;
                tmp.sub_assign(o);

                Some(tmp)
            }
            _ => None,
        }
    }
    fn mul(&self, other: &Self) -> Self {
        match (self, other) {
            (Some(s), Some(o)) => {
                let mut tmp = *s;
                tmp.mul_assign(o);

                Some(tmp)
            }
            _ => None,
        }
    }
    fn fma(&self, to_mul: &Self, to_add: &Self) -> Self {
        match (self, to_mul, to_add) {
            (Some(s), Some(m), Some(a)) => {
                let mut tmp = *s;
                tmp.mul_assign(m);
                tmp.add_assign(a);

                Some(tmp)
            }
            _ => None,
        }
    }
    fn negate(&self) -> Self {
        match self {
            Some(s) => {
                let mut tmp = *s;
                tmp.negate();

                Some(tmp)
            }
            _ => None,
        }
    }
}

pub fn convert_bits_le<E, CS>(
    cs: &mut CS,
    value: FieldElement<E, E::Fs>,
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

    Ok(bits.into_iter().map(Boolean::from).collect())
}

pub fn field_into_allocated_bits_le_fixed<E: Engine, CS: ConstraintSystem<E>, F: PrimeField>(
    cs: &mut CS,
    value: FieldElement<E, F>,
    bit_length: usize,
) -> Result<Vec<AllocatedBit>, SynthesisError> {
    assert!(bit_length <= F::NUM_BITS as usize);
    // Deconstruct in big-endian bit order
    let values = match value.get_field_value() {
        Some(ref value) => {
            let mut field_char = BitIterator::new(F::char());

            let mut tmp = Vec::with_capacity(F::NUM_BITS as usize);

            let mut found_one = false;
            for b in BitIterator::new(value.into_repr()) {
                // Skip leading bits
                found_one |= field_char.next().unwrap();
                if !found_one {
                    continue;
                }

                tmp.push(Some(b));
            }

            assert_eq!(tmp.len(), F::NUM_BITS as usize);

            tmp
        }
        None => vec![None; F::NUM_BITS as usize],
    };

    // Allocate in little-endian order
    let bits = values
        .into_iter()
        .rev()
        .enumerate()
        .take(bit_length)
        .map(|(_, b)| AllocatedBit::alloc(cs, b))
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    Ok(bits)
}

pub fn split_into_fixed_number_of_bits<F: PrimeField>(
    fe: &Option<F>,
    num_bits: usize,
) -> Vec<Option<bool>> {
    if let Some(value) = fe {
        let mut value = fe_to_biguint(value);
        let mut limbs = Vec::with_capacity(num_bits);

        let modulus = BigUint::from(2u64);
        for _ in 0..num_bits {
            let limb = value.clone() % &modulus;
            limbs.push(Some(!limb.is_zero()));
            value >>= 1;
        }

        limbs
    } else {
        vec![None; num_bits]
    }
}

pub fn allocate_edwards_point<E: JubjubEngine, CS: ConstraintSystem<E>, Subgroup>(
    cs: &mut CS,
    value: &Option<edwards::Point<E, Subgroup>>,
    jubjub_params: &E::Params,
) -> Result<EdwardsPoint<E>, SynthesisError> {
    let raw = if let Some(c) = value {
        let (x, y) = c.into_xy();
        (Some(x), Some(y))
    } else {
        (None, None)
    };
    let x = AllocatedNum::alloc(cs, || raw.0.ok_or(SynthesisError::UnconstrainedVariable))?;
    let y = AllocatedNum::alloc(cs, || raw.1.ok_or(SynthesisError::UnconstrainedVariable))?;

    let result = EdwardsPoint::interpret(cs, &x, &y, jubjub_params)?;

    Ok(result)
}
