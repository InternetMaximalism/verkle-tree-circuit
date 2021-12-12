pub mod utils;

use std::io::{Error, ErrorKind};

use franklin_crypto::bellman::pairing::ff::Field;
use franklin_crypto::bellman::pairing::{CurveAffine, Engine};
use franklin_crypto::bellman::plonk::better_better_cs::cs::{
  Circuit, ConstraintSystem, Gate, GateInternal, Width4MainGateWithDNext,
};
use franklin_crypto::bellman::SynthesisError;
use franklin_crypto::plonk::circuit::allocated_num::AllocatedNum;
use franklin_crypto::plonk::circuit::bigint::field::RnsParameters;
use franklin_crypto::plonk::circuit::bigint::range_constraint_gate::TwoBitDecompositionRangecheckCustomGate;
use franklin_crypto::plonk::circuit::linear_combination::LinearCombination;
use franklin_crypto::plonk::circuit::sha256::sha256 as sha256_circuit_hash;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::aux_data::AuxData;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::WrappedAffinePoint;

use self::utils::{bytes_to_keep, serialize_point_into_big_endian};

// Compute `H = aG` where `G`, `H` are elliptic curve elements and `a` is an finite field element.
// `G`, `H` are public variables, while `a` is an private variable.
// It is difficult to compute `a` using only `G` and `H` because discrete logarithm assumption.
// So only those who know `a` will be able to pass this verification.
pub struct DiscreteLogCircuit<'a, E: Engine, WP: WrappedAffinePoint<'a, E>, AD: AuxData<E>> {
  pub base_point: Option<E::G1Affine>,
  pub coefficient: Option<<E::G1Affine as CurveAffine>::Scalar>,
  pub rns_params: &'a RnsParameters<E, <E::G1Affine as CurveAffine>::Base>, // ?
  pub aux_data: AD,                                                         // ?
  pub _m: std::marker::PhantomData<WP>,
}

impl<'a, E: Engine, AD: AuxData<E>, WP: WrappedAffinePoint<'a, E>>
  DiscreteLogCircuit<'a, E, WP, AD>
{
  pub fn run<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<WP, SynthesisError> {
    let mut wrapped_base_point = WP::alloc(cs, self.base_point, &self.rns_params, &self.aux_data)?;
    let wrapped_coefficient = AllocatedNum::alloc(cs, || Ok(self.coefficient.unwrap()))?;
    let bit_limit = Some(256usize);

    let output = wrapped_base_point.mul(
      cs,
      &wrapped_coefficient,
      bit_limit,
      &self.rns_params,
      &self.aux_data,
    );

    output
  }
}

impl<'a, E: Engine, AD: AuxData<E>, WP: WrappedAffinePoint<'a, E>> Circuit<E>
  for DiscreteLogCircuit<'a, E, WP, AD>
{
  type MainGate = Width4MainGateWithDNext; // ?

  fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
    Ok(vec![
      Self::MainGate::default().into_internal(),
      TwoBitDecompositionRangecheckCustomGate::default().into_internal(),
    ])
  }

  fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
    let wrapped_output = match self.run(cs) {
      Ok(result) => result,
      Err(error) => {
        return Err(Error::new(ErrorKind::InvalidData, error).into());
      }
    };
    let mut hash_to_public_inputs = vec![];
    hash_to_public_inputs.extend(serialize_point_into_big_endian(cs, &wrapped_output)?);
    let input_commitment = sha256_circuit_hash(cs, &hash_to_public_inputs)?;

    let keep = bytes_to_keep::<E>();
    assert!(keep <= 32);

    // we don't need to reverse again

    let mut lc = LinearCombination::<E>::zero();

    let mut coeff = E::Fr::one();

    for b in input_commitment[(32 - keep) * 8..].iter().rev() {
      lc.add_assign_boolean_with_coeff(b, coeff);
      coeff.double();
    }

    let as_num = lc.into_allocated_num(cs)?;

    as_num.inputize(cs)?;

    Ok(())
  }
}
