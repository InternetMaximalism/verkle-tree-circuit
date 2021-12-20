use std::marker::PhantomData;
use std::path::Path;

use franklin_crypto::bellman::kate_commitment::{Crs, CrsForMonomialForm};
use franklin_crypto::bellman::pairing::bn256::Bn256;
use franklin_crypto::bellman::pairing::ff::ScalarEngine;
use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::plonk::better_better_cs::cs::{
  Assembly, Circuit, SetupAssembly, SynthesisModeProve, Width4MainGateWithDNext,
};
use franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use franklin_crypto::bellman::plonk::better_better_cs::verifier::verify;
use franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;
use franklin_crypto::bellman::worker::Worker;
use franklin_crypto::bellman::{CurveProjective, SynthesisError};
use franklin_crypto::plonk::circuit::bigint::field::RnsParameters;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::aux_data::{
  AuxData, BN256AuxData,
};
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::without_flag_checked::WrapperChecked;
use franklin_crypto::plonk::circuit::verifier_circuit::channel::RescueChannelGadget;
use franklin_crypto::plonk::circuit::Width4WithCustomGates;
use franklin_crypto::rescue::bn256::Bn256RescueParams;

use crate::circuit::ipa::config::{IpaConfig, PrecomputedWeights};
use crate::circuit::ipa::proof::OptionIpaProof;
use crate::circuit::ipa::IpaCircuit;

use super::input::CircuitInput;

const NUM_IPA_ROUND: usize = 8; // log_2(common.POLY_DEGREE);
const DOMAIN_SIZE: usize = 256; // common.POLY_DEGREE;

pub fn run(circuit_input: CircuitInput) -> anyhow::Result<()> {
  let num_ipa_rounds = NUM_IPA_ROUND; // log_2(DOMAIN_SIZE)

  // setup
  let mut assembly = SetupAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
  let rns_params = RnsParameters::<Bn256, <Bn256 as Engine>::Fq>::new_for_field(68, 110, 4);
  let dummy_aux_data = BN256AuxData::new();
  let mut srs = vec![];
  let rng = &mut rand::thread_rng();
  for _ in 0..DOMAIN_SIZE {
    let rand_point = <<Bn256 as Engine>::G1 as rand::Rand>::rand(rng);
    srs.push(rand_point);
  }
  let q = <Bn256 as Engine>::G1::one(); // base point
  let precomputed_weights =
    PrecomputedWeights::<<<Bn256 as Engine>::G1 as CurveProjective>::Scalar>::new()?;
  let ic = IpaConfig::<<Bn256 as Engine>::G1> {
    srs,
    q,
    precomputed_weights,
    num_ipa_rounds,
  };
  let rescue_params = Bn256RescueParams::new_checked_2_into_1();
  let dummy_circuit =
    IpaCircuit::<Bn256, WrapperChecked<Bn256>, BN256AuxData, RescueChannelGadget<Bn256>> {
      commitment: None,
      proof: OptionIpaProof::with_depth(ic.num_ipa_rounds),
      eval_point: None,
      inner_prod: None,
      ic: ic.clone(),
      rns_params: &rns_params,
      aux_data: dummy_aux_data,
      transcript_params: &rescue_params,
      _m: PhantomData,
    };

  dummy_circuit.synthesize(&mut assembly)?;

  let worker = Worker::new();

  assembly.finalize();
  let setup = assembly.create_setup(&worker)?;

  let crs = Crs::<Bn256, CrsForMonomialForm>::crs_42(524288, &worker); // ?

  let vk = VerificationKey::<
    Bn256,
    IpaCircuit<Bn256, WrapperChecked<Bn256>, BN256AuxData, RescueChannelGadget<Bn256>>,
  >::from_setup(&setup, &worker, &crs)?;

  // prove
  let aux_data = BN256AuxData::new();
  let circuit =
    IpaCircuit::<Bn256, WrapperChecked<Bn256>, BN256AuxData, RescueChannelGadget<Bn256>> {
      commitment: circuit_input.commitment,
      proof: OptionIpaProof::<<Bn256 as Engine>::G1>::from(circuit_input.proof.unwrap()),
      eval_point: circuit_input.eval_point,
      inner_prod: circuit_input.inner_prod,
      ic: ic.clone(),
      rns_params: &rns_params,
      aux_data,
      transcript_params: &rescue_params,
      _m: PhantomData,
    };

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
  let is_valid =
    verify::<_, _, RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>>(&vk, &proof, None)?;

  if is_valid == false {
    println!("Proof is invalid");
    return Err(SynthesisError::Unsatisfiable.into());
  }

  Ok(())
}

pub fn run_with_file(input_path: &Path) -> anyhow::Result<()> {
  let circuit_input = CircuitInput::from_path(input_path)?;
  run(circuit_input)
}
