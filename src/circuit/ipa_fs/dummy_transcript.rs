use franklin_crypto::babyjubjub::JubjubEngine;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use franklin_crypto::bellman::SynthesisError;
use franklin_crypto::plonk::circuit::allocated_num::AllocatedNum;
use franklin_crypto::plonk::circuit::assignment::Assignment;
use franklin_crypto::plonk::circuit::bigint::bigint::{biguint_to_fe, fe_to_biguint};
use franklin_crypto::plonk::circuit::bigint::field::{FieldElement, RnsParameters};
use generic_array::typenum;
use num_bigint::BigUint;
use verkle_tree::ff_utils::bn256_fr::Bn256Fr;
use verkle_tree::ff_utils::utils::{FromBytes, ToBytes};
use verkle_tree::neptune::poseidon::PoseidonConstants;
use verkle_tree::neptune::Poseidon;

use crate::circuit::num::baby_ecc::EdwardsPoint;
// use crate::circuit::poseidon_fs::calc_poseidon;

use super::transcript::Transcript;
use super::utils::{convert_fr_to_fs, convert_fs_to_fr};

#[derive(Clone)]
pub struct WrappedDummyTranscript<E>
where
    E: JubjubEngine,
{
    state: AllocatedNum<E>,
}

impl<E> Transcript<E> for WrappedDummyTranscript<E>
where
    E: JubjubEngine,
{
    type Params = AllocatedNum<E>;

    fn new<CS: ConstraintSystem<E>>(_cs: &mut CS, init_state: AllocatedNum<E>) -> Self {
        Self { state: init_state }
    }

    fn commit_field_element<'a, CS: ConstraintSystem<E>>(
        &mut self,
        cs: &mut CS,
        element: &FieldElement<'a, E, E::Fs>,
    ) -> Result<(), SynthesisError> {
        let element_fr = element
            .get_field_value()
            .map(|e| convert_fs_to_fr::<E>(&e).unwrap());
        let wrapped_element = AllocatedNum::<E>::alloc(cs, || {
            element_fr.ok_or(SynthesisError::UnconstrainedVariable)
        })?;
        self.commit_alloc_num(cs, &wrapped_element)?;

        Ok(())
    }

    /// Commit a `WP` value.

    fn commit_point<CS: ConstraintSystem<E>>(
        &mut self,
        cs: &mut CS,
        point: &EdwardsPoint<E>,
    ) -> Result<(), SynthesisError> {
        let point_x = point.get_x();
        self.commit_alloc_num(cs, point_x)?;
        let point_y = point.get_y();
        self.commit_alloc_num(cs, point_y)?;

        Ok(())
    }

    fn get_challenge<'a, CS: ConstraintSystem<E>>(
        &mut self,
        cs: &mut CS,
        rns_params: &'a RnsParameters<E, E::Fs>,
    ) -> Result<FieldElement<'a, E, E::Fs>, SynthesisError> {
        let result = convert_fr_to_fs(cs, &self.state).unwrap();
        let wrapped_result = FieldElement::new_allocated_in_field(cs, result, rns_params)?;

        Ok(wrapped_result)
    }

    fn into_params(self) -> AllocatedNum<E> {
        self.state
    }
}
// E = Bn256
impl<E> WrappedDummyTranscript<E>
where
    E: JubjubEngine,
{
    /// Commit a `AllocatedNum` value.
    /// NOTE: unconstrained about updating transcript
    fn commit_alloc_num<CS: ConstraintSystem<E>>(
        &mut self,
        cs: &mut CS,
        element: &AllocatedNum<E>,
    ) -> Result<(), SynthesisError> {
        let new_state = match (self.state.get_value(), element.get_value()) {
            (Some(state), Some(element)) => {
                let mut preimage = vec![<Bn256Fr as verkle_tree::ff::Field>::zero(); 2];
                let constants = PoseidonConstants::new();
                let state_uint = fe_to_biguint(&state);
                let element_uint = fe_to_biguint(&element);
                preimage[0] = Bn256Fr::from_bytes_le(&state_uint.to_bytes_le()).unwrap();
                preimage[1] = Bn256Fr::from_bytes_le(&element_uint.to_bytes_le()).unwrap();

                let mut h =
                    Poseidon::<Bn256Fr, typenum::U2>::new_with_preimage(&preimage, &constants);

                let new_state_uint = BigUint::from_bytes_le(&h.hash().to_bytes_le().unwrap());
                let new_state = biguint_to_fe(new_state_uint);
                Some(new_state)
            }
            _ => None,
        };

        self.state = AllocatedNum::alloc(cs, || new_state.grab()).unwrap();

        Ok(())
    }
}
