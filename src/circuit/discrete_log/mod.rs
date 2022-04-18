pub mod utils;

use franklin_crypto::babyjubjub::{edwards, JubjubEngine, Unknown};
use franklin_crypto::bellman::plonk::better_better_cs::cs::{ArithmeticTerm, MainGateTerm};
use franklin_crypto::bellman::{
    plonk::better_better_cs::cs::{
        Circuit, ConstraintSystem, Gate, GateInternal, Width4MainGateWithDNext,
    },
    {PrimeField, SynthesisError},
};
use franklin_crypto::plonk::circuit::{
    bigint::field::RnsParameters,
    bigint::range_constraint_gate::TwoBitDecompositionRangecheckCustomGate,
    boolean::{AllocatedBit, Boolean},
    verifier_circuit::affine_point_wrapper::aux_data::AuxData,
    verifier_circuit::affine_point_wrapper::without_flag_unchecked::WrapperUnchecked,
    verifier_circuit::affine_point_wrapper::WrappedAffinePoint,
};
use verkle_tree::ipa_fr::{
    config::{Committer, IpaConfig},
    rns::BaseRnsParameters,
    utils::test_poly,
};

use crate::circuit::num::baby_ecc::EdwardsPoint;

use super::num::{allocate_edwards_point, split_into_fixed_number_of_bits};

// Compute `H = aG` where `G`, `H` are elliptic curve elements and `a` is an finite field element.
// `G`, `H` are public variables, while `a` is an private variable.
// It is difficult to compute `a` using only `G` and `H` because discrete logarithm assumption.
// So only those who know `a` will be able to pass this verification.
pub struct DiscreteLogCircuit<'a, E: JubjubEngine, AD: AuxData<E>> {
    pub base_point: Option<edwards::Point<E, Unknown>>,
    pub coefficient: Option<E::Fs>,
    pub output: Option<edwards::Point<E, Unknown>>,
    pub rns_params: &'a RnsParameters<E, E::Fs>,
    pub aux_data: AD,
    pub jubjub_params: &'a E::Params,
}

impl<'a, E: JubjubEngine, AD: AuxData<E>> DiscreteLogCircuit<'a, E, AD> {
    pub fn run<CS: ConstraintSystem<E>>(
        &self,
        cs: &mut CS,
    ) -> Result<(EdwardsPoint<E>, EdwardsPoint<E>), SynthesisError> {
        let wrapped_base_point = allocate_edwards_point(cs, &self.base_point, self.jubjub_params)?;
        let coefficient_bits = split_into_fixed_number_of_bits(
            &self.coefficient,
            <E::Fs as PrimeField>::NUM_BITS as usize,
        );

        let wrapped_coefficient_bits = coefficient_bits
            .iter()
            .map(|v| AllocatedBit::alloc(cs, *v).map(Boolean::from))
            .collect::<Result<Vec<Boolean>, SynthesisError>>()?;

        let wrapped_output =
            wrapped_base_point.mul(cs, &wrapped_coefficient_bits, self.jubjub_params)?;
        let self_wrapped_output = allocate_edwards_point(cs, &self.output, self.jubjub_params)?;
        {
            let wrapped_output_term =
                ArithmeticTerm::<E>::from_variable(wrapped_output.get_x().get_variable());
            let self_wrapped_output_term =
                ArithmeticTerm::from_variable(self_wrapped_output.get_x().get_variable());

            let mut term = MainGateTerm::new();
            term.add_assign(wrapped_output_term);
            term.sub_assign(self_wrapped_output_term);
            cs.allocate_main_gate(term)?;

            let wrapped_output_term =
                ArithmeticTerm::<E>::from_variable(wrapped_output.get_y().get_variable());
            let self_wrapped_output_term =
                ArithmeticTerm::from_variable(self_wrapped_output.get_y().get_variable());

            let mut term = MainGateTerm::new();
            term.add_assign(wrapped_output_term);
            term.sub_assign(self_wrapped_output_term);
            cs.allocate_main_gate(term)?;
        }

        // force to use TwoBitDecompositionRangecheckCustomGate
        // TODO: unnecessary code
        {
            let rns_params = BaseRnsParameters::<E>::new_for_field(68, 110, 4);
            let domain_size = 1;
            let ipa_conf = IpaConfig::<E::G1Affine>::new(domain_size);
            let poly = vec![1];
            let padded_poly = test_poly::<E::Fr>(&poly, domain_size);
            let some_point = ipa_conf.commit(&padded_poly).unwrap();
            let _wrapped_point =
                WrapperUnchecked::alloc(cs, Some(some_point), &rns_params, &self.aux_data)?;
        }

        Ok((wrapped_base_point, self_wrapped_output))
    }
}

impl<'a, E: JubjubEngine, AD: AuxData<E>> Circuit<E> for DiscreteLogCircuit<'a, E, AD> {
    type MainGate = Width4MainGateWithDNext;

    fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
        Ok(vec![
            Self::MainGate::default().into_internal(),
            TwoBitDecompositionRangecheckCustomGate::default().into_internal(),
        ])
    }

    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        let (wrapped_base_point, wrapped_output) = self.run(cs)?;

        // allocate public inputs
        wrapped_base_point.inputize(cs)?;
        wrapped_output.inputize(cs)?;

        Ok(())
    }
}
