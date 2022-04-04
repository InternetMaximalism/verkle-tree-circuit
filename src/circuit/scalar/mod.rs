// use std::io::{Error, ErrorKind};

use franklin_crypto::circuit::num::AllocatedNum;
use franklin_crypto::circuit::Assignment;
use franklin_crypto::{
    babyjubjub::JubjubEngine,
    bellman::{ConstraintSystem, Field, LinearCombination, PrimeField, SynthesisError, Variable},
    circuit::boolean::{self, Boolean},
};
use verkle_tree::ipa_fs::utils::{convert_fs_repr_to_fr_repr, convert_fs_to_fr};

pub struct Scalar<E: JubjubEngine> {
    value: Option<E::Fs>,
    variable: Variable,
}

impl<E: JubjubEngine> Clone for Scalar<E> {
    fn clone(&self) -> Self {
        Self {
            value: self.value,
            variable: self.variable,
        }
    }
}

pub fn add_range_check<E: JubjubEngine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    value: &AllocatedNum<E>,
    bit_length: u32,
) -> Result<(), SynthesisError> {
    assert!(bit_length <= E::Fr::NUM_BITS);

    let value_bits = value.into_bits_le(cs.namespace(|| "value into bits LE"))?;
    let false_var = Boolean::constant(false);
    for b in value_bits.iter().skip(bit_length as usize) {
        Boolean::enforce_equal(cs.namespace(|| "b is false"), b, &false_var)?;
    }

    Ok(())
}

impl<E: JubjubEngine> Scalar<E> {
    pub fn alloc<CS, F>(mut cs: CS, value: F) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<E>,
        F: FnOnce() -> Result<E::Fs, SynthesisError>,
    {
        let mut new_value = None;
        let var = cs.alloc(
            || "num",
            || {
                let tmp = value()?;

                new_value = Some(tmp);

                Ok(convert_fs_to_fr::<E>(&tmp).unwrap())
            },
        )?;

        let new_value_num = AllocatedNum::alloc(cs.namespace(|| "input variable"), || {
            Ok(convert_fs_to_fr::<E>(&new_value.unwrap()).unwrap())
        })?;
        let fs_char = E::Fs::char();
        let fs_char_fr = convert_fs_repr_to_fr_repr::<E>(&fs_char).unwrap();
        let fs_char_num = AllocatedNum::alloc(cs.namespace(|| "allocate Fs::char()"), || {
            Ok(E::Fr::from_repr(fs_char_fr).unwrap())
        })?;
        add_range_check(
            cs.namespace(|| "add min range check"),
            &new_value_num,
            E::Fs::NUM_BITS,
        )?;
        let range_max = fs_char_num.sub(cs.namespace(|| "compute range_max"), &new_value_num)?;
        add_range_check(
            cs.namespace(|| "add max range check"),
            &range_max,
            E::Fs::NUM_BITS,
        )?;

        Ok(Self {
            value: new_value,
            variable: var,
        })
    }

    pub fn inputize<CS>(&self, mut cs: CS) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<E>,
    {
        let input = AllocatedNum::alloc(cs.namespace(|| "input variable"), || {
            Ok(convert_fs_to_fr::<E>(&self.value.unwrap()).unwrap())
        })?;

        let fs_char = E::Fs::char();
        let fs_char_fr = convert_fs_repr_to_fr_repr::<E>(&fs_char).unwrap();
        let fs_char_num = AllocatedNum::alloc(cs.namespace(|| "allocate Fs::char()"), || {
            Ok(E::Fr::from_repr(fs_char_fr).unwrap())
        })?;
        let range_max = fs_char_num.sub(cs.namespace(|| "compute range_max"), &input)?;
        add_range_check(
            cs.namespace(|| "add min range check"),
            &input,
            E::Fs::NUM_BITS,
        )?;
        add_range_check(
            cs.namespace(|| "add max range check"),
            &range_max,
            E::Fs::NUM_BITS,
        )?;
        input.inputize(cs.namespace(|| "allocate input"))?;

        Ok(())
    }

    pub fn one<CS>() -> Self
    where
        CS: ConstraintSystem<E>,
    {
        let new_value = Some(E::Fs::one());

        Self {
            value: new_value,
            variable: CS::one(),
        }
    }

    pub fn zero<CS>(mut cs: CS) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<E>,
    {
        let value = Some(E::Fs::zero());

        let variable = cs.alloc(|| "zero num", || Ok(E::Fr::zero()))?;

        cs.enforce(
            || "enforce one is actually one",
            |lc| lc + variable,
            |lc| lc + CS::one(),
            |lc| lc,
        );

        Ok(Self { value, variable })
    }

    pub fn equals<CS>(
        mut cs: CS,
        a: &Self,
        b: &Self,
    ) -> Result<boolean::AllocatedBit, SynthesisError>
    where
        E: JubjubEngine,
        CS: ConstraintSystem<E>,
    {
        // Allocate and constrain `r`: result boolean bit.
        // It equals `true` if `a` equals `b`, `false` otherwise

        let r_value = match (a.value, b.value) {
            (Some(a), Some(b)) => Some(a == b),
            _ => None,
        };

        let r = boolean::AllocatedBit::alloc(cs.namespace(|| "r"), r_value)?;

        // Let `delta = a - b`

        let delta_value = match (a.value, b.value) {
            (Some(a), Some(b)) => {
                // return (a - b)
                let mut a = a;
                a.sub_assign(&b);
                Some(a)
            }
            _ => None,
        };

        let delta_inv_value = delta_value.as_ref().map(|delta_value| {
            let tmp = delta_value.clone();
            if tmp.is_zero() {
                E::Fs::one() // we can return any number here, it doesn't matter
            } else {
                tmp.inverse().unwrap()
            }
        });

        let delta_inv = Self::alloc(cs.namespace(|| "delta_inv"), || delta_inv_value.grab())?;

        // Allocate `t = delta * delta_inv`
        // If `delta` is non-zero (a != b), `t` will equal 1
        // If `delta` is zero (a == b), `t` cannot equal 1

        let t_value = match (delta_value, delta_inv_value) {
            (Some(a), Some(b)) => {
                let mut t = a.clone();
                t.mul_assign(&b);
                Some(t)
            }
            _ => None,
        };

        let t = Self::alloc(cs.namespace(|| "t"), || t_value.grab())?;

        // Constrain allocation:
        // t = (a - b) * delta_inv
        cs.enforce(
            || "t = (a - b) * delta_inv",
            |zero| zero + a.variable - b.variable,
            |zero| zero + delta_inv.variable,
            |zero| zero + t.variable,
        );

        // Constrain:
        // (a - b) * (t - 1) == 0
        // This enforces that correct `delta_inv` was provided,
        // and thus `t` is 1 if `(a - b)` is non zero (a != b )
        cs.enforce(
            || "(a - b) * (t - 1) == 0",
            |zero| zero + a.variable - b.variable,
            |zero| zero + t.variable - CS::one(),
            |zero| zero,
        );

        // Constrain:
        // (a - b) * r == 0
        // This enforces that `r` is zero if `(a - b)` is non-zero (a != b)
        cs.enforce(
            || "(a - b) * r == 0",
            |zero| zero + a.variable - b.variable,
            |zero| zero + r.get_variable(),
            |zero| zero,
        );

        // Constrain:
        // (t - 1) * (r - 1) == 0
        // This enforces that `r` is one if `t` is not one (a == b)
        cs.enforce(
            || "(t - 1) * (r - 1) == 0",
            |zero| zero + t.get_variable() - CS::one(),
            |zero| zero + r.get_variable() - CS::one(),
            |zero| zero,
        );

        Ok(r)
    }

    pub fn add<CS>(&self, mut cs: CS, other: &Self) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<E>,
    {
        let mut value = None;

        let variable = cs.alloc(
            || "add num",
            || {
                let mut tmp = *self.value.get()?;
                tmp.add_assign(other.value.get()?);

                value = Some(tmp);

                Ok(convert_fs_to_fr::<E>(&tmp).unwrap())
            },
        )?;

        // Constrain: a * b = ab
        cs.enforce(
            || "addition constraint",
            |zero| zero + self.variable + other.variable,
            |zero| zero + CS::one(),
            |zero| zero + variable,
        );

        Ok(Self { value, variable })
    }

    pub fn sub<CS>(&self, mut cs: CS, other: &Self) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<E>,
    {
        let mut value = None;

        let variable = cs.alloc(
            || "sub num",
            || {
                let mut tmp = *self.value.get()?;
                tmp.sub_assign(other.value.get()?);

                value = Some(tmp);

                Ok(convert_fs_to_fr::<E>(&tmp).unwrap())
            },
        )?;

        // Constrain: a * b = ab
        cs.enforce(
            || "addition constraint",
            |zero| zero + self.variable - other.variable,
            |zero| zero + CS::one(),
            |zero| zero + variable,
        );

        Ok(Self { value, variable })
    }

    pub fn into_bits_le<CS>(&self, mut cs: CS) -> Result<Vec<Boolean>, SynthesisError>
    where
        CS: ConstraintSystem<E>,
    {
        let bits = boolean::field_into_allocated_bits_le(&mut cs, self.value)?;

        let mut packed_lc = LinearCombination::zero();
        let mut coeff = E::Fr::one();

        for bit in bits.iter() {
            packed_lc = packed_lc + (coeff, bit.get_variable());

            coeff.double();
        }

        cs.enforce(
            || "unpacking constraint",
            |_| packed_lc,
            |zero| zero + CS::one(),
            |zero| zero + self.get_variable(),
        );

        Ok(bits.into_iter().map(|b| Boolean::from(b)).collect())
    }

    pub fn get_value(&self) -> Option<E::Fs> {
        self.value
    }

    pub fn get_variable(&self) -> Variable {
        self.variable
    }
}
