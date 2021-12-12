use std::marker::PhantomData;
use std::path::Path;

use franklin_crypto::bellman::SynthesisError;
use franklin_crypto::bellman::kate_commitment::{Crs, CrsForMonomialForm};
use franklin_crypto::bellman::pairing::bn256::Bn256;
use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::pairing::ff::ScalarEngine;
use franklin_crypto::plonk::circuit::bigint::field::RnsParameters;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::without_flag_unchecked::WrapperUnchecked;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::aux_data::{BN256AuxData, AuxData};
use franklin_crypto::bellman::plonk::better_better_cs::cs::{Circuit, SetupAssembly, Width4MainGateWithDNext, Assembly, SynthesisModeProve};
use franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use franklin_crypto::plonk::circuit::Width4WithCustomGates;

use crate::circuit::discrete_log::DiscreteLogCircuit;

use super::input::CircuitInput;

pub fn run<'a>(circuit_input: CircuitInput) -> anyhow::Result<()> {
  // setup
  let mut assembly = SetupAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
  let rns_params = RnsParameters::<Bn256, <Bn256 as Engine>::Fq>::new_for_field(68, 110, 4);
  let dummy_aux_data = BN256AuxData::new();
  let dummy_input = CircuitInput::default();
  let dummy_circuit = DiscreteLogCircuit::<Bn256, WrapperUnchecked<Bn256>, BN256AuxData> {
    base_point: dummy_input.base_point,
    coefficient: dummy_input.coefficient,
    rns_params: &rns_params,
    aux_data: dummy_aux_data,
    _m: PhantomData,
  };

  dummy_circuit.synthesize(&mut assembly)?;

  use franklin_crypto::bellman::worker::*;
  let worker = Worker::new();

  assembly.finalize();
  let setup = assembly.create_setup(&worker)?;

  let crs = Crs::<Bn256, CrsForMonomialForm>::crs_42(32, &worker);

  let vk = VerificationKey::<
    Bn256,
    DiscreteLogCircuit<Bn256, WrapperUnchecked<Bn256>, BN256AuxData>,
  >::from_setup(&setup, &worker, &crs)?;

  // prove
  let aux_data = BN256AuxData::new();
  let circuit = DiscreteLogCircuit::<Bn256, WrapperUnchecked<Bn256>, BN256AuxData> {
    base_point: circuit_input.base_point,
    coefficient: circuit_input.coefficient,
    rns_params: &rns_params,
    aux_data,
    _m: PhantomData,
  };

  use franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;

  let mut assembly =
    Assembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext, SynthesisModeProve>::new();
  circuit.synthesize(&mut assembly).expect("must synthesize");
  assembly.finalize();

  let proof = assembly
    .create_proof::<_, RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>>(
      &worker, &setup, &crs, None,
    )
    .expect("must check if satisfied and make a proof");

  // verify
  use franklin_crypto::bellman::plonk::better_better_cs::verifier::verify;

  let is_valid =
    verify::<_, _, RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>>(&vk, &proof, None)?;

  if is_valid == false {
    println!("Recursive circuit proof is invalid");
    return Err(SynthesisError::Unsatisfiable.into());
  }

  Ok(())
}

pub fn run_with_file(input_path: &Path) -> anyhow::Result<()> {
  let circuit_input = CircuitInput::from_path(input_path)?;
  run(circuit_input)
}
