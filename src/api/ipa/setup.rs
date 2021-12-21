use std::fs::OpenOptions;
use std::marker::PhantomData;
use std::path::Path;

// use franklin_crypto::alt_babyjubjub::AltJubjubBn256;
// use franklin_crypto::babyjubjub::JubjubEngine;
use franklin_crypto::bellman::kate_commitment::{Crs, CrsForMonomialForm};
use franklin_crypto::bellman::pairing::bn256::Bn256;
use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::plonk::better_better_cs::cs::{
  Circuit, SetupAssembly, Width4MainGateWithDNext,
};
use franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use franklin_crypto::bellman::worker::Worker;
use franklin_crypto::bellman::CurveProjective;

use franklin_crypto::plonk::circuit::bigint::field::RnsParameters;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::aux_data::{
  AuxData, BN256AuxData,
};
// use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::without_flag_unchecked::WrapperUnchecked;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::without_flag_checked::WrapperChecked;
use franklin_crypto::plonk::circuit::verifier_circuit::channel::RescueChannelGadget;
use franklin_crypto::plonk::circuit::Width4WithCustomGates;
use franklin_crypto::rescue::bn256::Bn256RescueParams;

use crate::circuit::ipa::config::{IpaConfig, PrecomputedWeights, DOMAIN_SIZE, NUM_IPA_ROUND};
use crate::circuit::ipa::proof::OptionIpaProof;
use crate::circuit::ipa::IpaCircuit;

pub fn generate_random_parameters_with_file(
  crs_path: &Path,
  _pk_path: &Path,
  _vk_path: &Path,
) -> anyhow::Result<()> {
  let num_ipa_rounds = NUM_IPA_ROUND; // log_2(DOMAIN_SIZE)

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

  let mut assembly = SetupAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
  dummy_circuit.synthesize(&mut assembly)?;

  assembly.finalize();

  println!("num_input_gates: {}", assembly.num_input_gates);
  println!("num_aux_gates: {}", assembly.num_aux_gates);
  println!("max_constraint_degree: {}", assembly.max_constraint_degree);
  println!("num_inputs: {}", assembly.num_inputs);
  println!("num_aux: {}", assembly.num_aux);
  println!(
    "total_length_of_all_tables: {}",
    assembly.total_length_of_all_tables
  );
  println!("num_table_lookups: {}", assembly.num_table_lookups);
  println!(
    "num_multitable_lookups: {}",
    assembly.num_multitable_lookups
  );

  println!("create_setup");
  let worker = Worker::new();
  let setup = assembly.create_setup(&worker)?;

  println!("crs");
  let crs_file = OpenOptions::new().read(true).open(crs_path)?;
  let crs = Crs::<Bn256, CrsForMonomialForm>::read(crs_file)?;

  println!("vk");
  let _vk = VerificationKey::<
    Bn256,
    IpaCircuit<Bn256, WrapperChecked<Bn256>, BN256AuxData, RescueChannelGadget<Bn256>>,
  >::from_setup(&setup, &worker, &crs)?;

  Ok(())
}
