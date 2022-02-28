use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use franklin_crypto::bellman::{PrimeField, SynthesisError};
use franklin_crypto::plonk::circuit::allocated_num::{AllocatedNum, Num};
use franklin_crypto::plonk::circuit::bigint::field::FieldElement;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::WrappedAffinePoint;

use crate::circuit::poseidon::calc_poseidon;

pub trait Transcript<E: Engine>: Sized + Clone {
    type Params;

    fn new(init_state: Self::Params) -> Self;
    fn commit_alloc_num<CS: ConstraintSystem<E>>(
        &mut self,
        cs: &mut CS,
        element: AllocatedNum<E>,
    ) -> Result<(), SynthesisError>;
    fn commit_point<'a, CS: ConstraintSystem<E>, WP: WrappedAffinePoint<'a, E>>(
        &mut self,
        cs: &mut CS,
        point: &WP,
    ) -> Result<(), SynthesisError>;
    fn into_params(self) -> Self::Params;
    fn get_challenge(&mut self) -> AllocatedNum<E>;
}

#[derive(Clone)]
pub struct WrappedTranscript<E>
where
    E: Engine,
{
    state: AllocatedNum<E>,
}

impl<E: Engine> Transcript<E> for WrappedTranscript<E> {
    type Params = AllocatedNum<E>;

    fn new(init_state: AllocatedNum<E>) -> Self {
        Self { state: init_state }
    }

    fn commit_alloc_num<CS: ConstraintSystem<E>>(
        &mut self,
        cs: &mut CS,
        element: AllocatedNum<E>,
    ) -> Result<(), SynthesisError> {
        let inputs = vec![self.state, element];
        self.state = calc_poseidon(cs, &inputs)?;

        Ok(())
    }

    fn get_challenge(&mut self) -> AllocatedNum<E> {
        self.state
    }

    fn commit_point<'a, CS: ConstraintSystem<E>, WP: WrappedAffinePoint<'a, E>>(
        &mut self,
        cs: &mut CS,
        point: &WP,
    ) -> Result<(), SynthesisError> {
        let unwrapped_point = point.get_point();
        let point_x = unwrapped_point.get_x();
        self.commit_field_element(cs, point_x)?;
        let point_y = unwrapped_point.get_y();
        self.commit_field_element(cs, point_y)?;

        Ok(())
    }

    fn into_params(self) -> Self::Params {
        self.state
    }
}

impl<E: Engine> WrappedTranscript<E> {
    pub fn commit_fr<CS: ConstraintSystem<E>>(
        &mut self,
        cs: &mut CS,
        element: Option<E::Fr>,
    ) -> Result<(), SynthesisError> {
        let input = AllocatedNum::alloc(cs, || Ok(element.unwrap()))?;
        self.commit_alloc_num(cs, input)?;

        Ok(())
    }

    pub fn commit_field_element<'a, CS: ConstraintSystem<E>, F: PrimeField>(
        &mut self,
        cs: &mut CS,
        element: FieldElement<'a, E, F>,
    ) -> Result<(), SynthesisError> {
        let value = element.value;
        for term in element.into_limbs().iter() {
            let v = if let Some(_) = value {
                match term.into_num() {
                    Num::Constant(c) => AllocatedNum::alloc(cs, || Ok(c))?,
                    Num::Variable(v) => v,
                }
            } else {
                AllocatedNum::alloc(cs, || Err(SynthesisError::UnconstrainedVariable))?
            };

            self.commit_alloc_num(cs, v)?;
        }

        Ok(())
    }

    pub fn commit_wrapped_affine<'a, CS: ConstraintSystem<E>, WP: WrappedAffinePoint<'a, E>>(
        &mut self,
        cs: &mut CS,
        element: WP,
    ) -> Result<(), SynthesisError> {
        self.commit_field_element(cs, element.get_point().get_x())?;
        self.commit_field_element(cs, element.get_point().get_y())?;

        Ok(())
    }
}
