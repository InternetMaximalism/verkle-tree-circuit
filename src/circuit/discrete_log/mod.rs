pub mod utils;

use std::marker::PhantomData;

use franklin_crypto::babyjubjub::JubjubEngine;
use franklin_crypto::bellman::PrimeField;
use franklin_crypto::bellman::{Circuit, ConstraintSystem, SynthesisError};
use franklin_crypto::circuit::baby_ecc::EdwardsPoint;
use franklin_crypto::circuit::num::AllocatedNum;

use crate::circuit::ipa_fs::utils::convert_bits_le;

// Compute `H = aG` where `G`, `H` are elliptic curve elements and `a` is an finite field element.
// `G`, `H` are public variables, while `a` is an private variable.
// It is difficult to compute `a` using only `G` and `H` because discrete logarithm assumption.
// So only those who know `a` will be able to pass this verification.
pub struct DiscreteLogCircuit<E: JubjubEngine> {
    pub base_point_x: Option<E::Fr>,
    pub base_point_y: Option<E::Fr>,
    pub coefficient: Option<E::Fs>,
    pub jubjub_params: E::Params,
    pub _m: PhantomData<E>,
}

impl<E: JubjubEngine> DiscreteLogCircuit<E> {
    pub fn run<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS,
    ) -> Result<EdwardsPoint<E>, SynthesisError> {
        let wrapped_base_point_x = AllocatedNum::alloc(cs.namespace(|| "base_point_x"), || {
            Ok(self.base_point_x.unwrap())
        })?;
        let wrapped_base_point_y = AllocatedNum::alloc(cs.namespace(|| "base_point_y"), || {
            Ok(self.base_point_y.unwrap())
        })?;
        let wrapped_base_point = EdwardsPoint::interpret(
            cs.namespace(|| "base_point"),
            &wrapped_base_point_x,
            &wrapped_base_point_y,
            &self.jubjub_params,
        )?;
        // let wrapped_coefficient = AllocatedNum::alloc(cs.namespace(|| "coefficient"), || {
        //     Ok(self.coefficient.unwrap())
        // })?;

        // let wrapped_coefficient_bits = wrapped_coefficient.into_bits_le_fixed(
        //     cs.namespace(|| "coefficient_into_bits_le_fixed"),
        //     E::Fs::NUM_BITS as usize,
        // )?;
        let wrapped_coefficient_bits = convert_bits_le(cs, self.coefficient, None)?;
        let wrapped_output = wrapped_base_point.mul(
            cs.namespace(|| "output"),
            &wrapped_coefficient_bits,
            &self.jubjub_params,
        )?;
        // let wrapped_output =
        //     wrapped_output.double(cs.namespace(|| "add_output"), &self.jubjub_params)?;
        // let wrapped_output = wrapped_base_point;

        println!(
            "wrapped_output: ({:?}, {:?})",
            wrapped_output.get_x().get_value(),
            wrapped_output.get_y().get_value()
        );

        Ok(wrapped_output)
    }
}

impl<E: JubjubEngine> Circuit<E> for DiscreteLogCircuit<E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let wrapped_output = self.run(cs)?;

        wrapped_output.inputize(cs.namespace(|| "alloc_output"))
    }
}
