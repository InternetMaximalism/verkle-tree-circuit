pub mod utils;

use franklin_crypto::babyjubjub::{edwards, JubjubEngine, Unknown};
use franklin_crypto::bellman::plonk::better_better_cs::cs::{
    Circuit, ConstraintSystem, Gate, GateInternal, Width4MainGateWithDNext,
};
use franklin_crypto::bellman::SynthesisError;
use franklin_crypto::plonk::circuit::allocated_num::AllocatedNum;
use franklin_crypto::plonk::circuit::bigint::field::{FieldElement, RnsParameters};
use franklin_crypto::plonk::circuit::bigint::range_constraint_gate::TwoBitDecompositionRangecheckCustomGate;

use crate::circuit::ipa_fs::utils::convert_bits_le;
use crate::circuit::num::baby_ecc::EdwardsPoint;

// Compute `H = aG` where `G`, `H` are elliptic curve elements and `a` is an finite field element.
// `G`, `H` are public variables, while `a` is an private variable.
// It is difficult to compute `a` using only `G` and `H` because discrete logarithm assumption.
// So only those who know `a` will be able to pass this verification.
pub struct DiscreteLogCircuit<'a, E: JubjubEngine> {
    pub base_point: Option<edwards::Point<E, Unknown>>,
    pub coefficient: Option<E::Fs>,
    pub rns_params: &'a RnsParameters<E, E::Fs>,
    pub jubjub_params: &'a E::Params,
}

impl<'a, E: JubjubEngine> DiscreteLogCircuit<'a, E> {
    pub fn run<CS: ConstraintSystem<E>>(
        &self,
        cs: &mut CS,
    ) -> Result<EdwardsPoint<E>, SynthesisError> {
        let wrapped_base_point = {
            let raw = if let Some(c) = &self.base_point {
                let (x, y) = c.into_xy();
                (Some(x), Some(y))
            } else {
                (None, None)
            };
            let x = AllocatedNum::alloc(cs, || raw.0.ok_or(SynthesisError::UnconstrainedVariable))?;
            let y = AllocatedNum::alloc(cs, || raw.1.ok_or(SynthesisError::UnconstrainedVariable))?;

            EdwardsPoint::interpret(cs, &x, &y, self.jubjub_params)?
        };
        let coefficient =
            FieldElement::new_allocated_in_field(cs, self.coefficient, self.rns_params)?;
        let wrapped_coefficient_bits = convert_bits_le(cs, coefficient, None)?;
        let wrapped_output =
            wrapped_base_point.mul(cs, &wrapped_coefficient_bits, &self.jubjub_params)?;
        wrapped_output.inputize(cs)?;

        Ok(wrapped_output)
    }
}

impl<'a, E: JubjubEngine> Circuit<E> for DiscreteLogCircuit<'a, E> {
    type MainGate = Width4MainGateWithDNext;

    fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
        Ok(vec![
            Self::MainGate::default().into_internal(),
            TwoBitDecompositionRangecheckCustomGate::default().into_internal(),
        ])
    }

    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        let wrapped_output = self.run(cs)?;

        wrapped_output.inputize(cs)
    }
}
