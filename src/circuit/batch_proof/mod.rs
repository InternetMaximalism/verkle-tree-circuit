use franklin_crypto::bellman::pairing::{CurveProjective, Engine};
use franklin_crypto::bellman::plonk::commitments::transcript::Transcript;
use franklin_crypto::bellman::{Circuit, ConstraintSystem, Field, SynthesisError};
use franklin_crypto::circuit::ecc::EdwardsPoint;
use franklin_crypto::circuit::num::AllocatedNum;
use franklin_crypto::jubjub::JubjubEngine;

use super::ipa::{config::IpaConfig, proof::IpaProof};

pub struct BatchProofCircuit<'a, E: JubjubEngine, T: Transcript<E::Fr>> {
  pub proof: Option<IpaProof<E>>,
  pub d: Option<E::G1>,
  pub commitments: Option<Vec<E::G1>>,
  pub ys: Option<Vec<<E::G1 as CurveProjective>::Scalar>>,
  pub zs: Option<Vec<u8>>,
  pub ipa_conf: IpaConfig<E>,
  pub jubjub_params: &'a E::Params,
  pub _transcript_params: std::marker::PhantomData<T>,
}

impl<'a, E: JubjubEngine, T: Transcript<E::Fr>> Circuit<E> for BatchProofCircuit<'a, E, T> {
  fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
    Ok(())
  }
}
