use std::marker::PhantomData;
use std::path::Path;

// use franklin_crypto::alt_babyjubjub::AltJubjubBn256;
// use franklin_crypto::babyjubjub::JubjubEngine;
use franklin_crypto::alt_babyjubjub::AltJubjubBn256;
use franklin_crypto::bellman::groth16::generate_random_parameters;
use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr, FrRepr};
use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::plonk::commitments::transcript::Blake2sTranscript;
use franklin_crypto::bellman::{CurveProjective, PrimeField};

// use franklin_crypto::plonk::circuit::bigint::field::RnsParameters;
// use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::aux_data::{
//   AuxData, BN256AuxData,
// };
// use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::without_flag_unchecked::WrapperUnchecked;
// use franklin_crypto::plonk::circuit::verifier_circuit::channel::RescueChannelGadget;
// use franklin_crypto::rescue::bn256::Bn256RescueParams;

use crate::circuit::ipa::config::{IpaConfig, PrecomputedWeights, DOMAIN_SIZE, NUM_IPA_ROUNDS};
use crate::circuit::ipa::proof::OptionIpaProof;
use crate::circuit::ipa::IpaCircuit;

pub fn generate_random_parameters_with_file(
  _pk_path: &Path,
  _vk_path: &Path,
) -> anyhow::Result<()> {
  let num_ipa_rounds = NUM_IPA_ROUNDS; // log_2(DOMAIN_SIZE)

  let jubjub_params = AltJubjubBn256::new();
  // let rns_params = RnsParameters::<Bn256, <Bn256 as Engine>::Fq>::new_for_field(68, 110, 4);
  // let dummy_aux_data = BN256AuxData::new();
  let mut srs = vec![];
  let rng = &mut rand::thread_rng();
  for _ in 0..DOMAIN_SIZE {
    let rand_point = (<Fr as rand::Rand>::rand(rng), <Fr as rand::Rand>::rand(rng));
    srs.push(rand_point);
  }

  let edwards_base_x = Fr::from_repr(FrRepr([
    0xe1e71866a252ae18u64,
    0x2b79c022ad998465,
    0x743711777bbe42f3,
    0x29c132cc2c0b34c5,
  ]))?;
  let edwards_base_y = Fr::from_repr(FrRepr([
    0x5e3167b6cc974166u64,
    0x358cad81eee46460,
    0x157d8b50badcd586,
    0x2a6c669eda123e0f,
  ]))?;
  let edwards_base = (edwards_base_x, edwards_base_y);
  println!("edwards_base: {:?}", edwards_base);

  let precomputed_weights =
    PrecomputedWeights::<<<Bn256 as Engine>::G1 as CurveProjective>::Scalar>::new()?;
  let ipa_conf = IpaConfig::<Bn256> {
    srs,
    q: edwards_base,
    precomputed_weights,
    num_ipa_rounds,
  };
  // let rescue_params = Bn256RescueParams::new_checked_2_into_1();
  let dummy_circuit = IpaCircuit::<Bn256, Blake2sTranscript<Fr>> {
    commitment: None,
    proof: OptionIpaProof::with_depth(ipa_conf.num_ipa_rounds),
    eval_point: None,
    inner_prod: None,
    ipa_conf: ipa_conf.clone(),
    jubjub_params: &jubjub_params,
    _transcript_params: PhantomData,
  };

  // let mut assembly = SetupAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
  // dummy_circuit.synthesize(&mut assembly)?;

  // assembly.finalize();

  println!("create_setup");
  // let worker = Worker::new();
  // let setup = assembly.create_setup(&worker)?;

  let rng = &mut rand::thread_rng();
  let _setup = generate_random_parameters::<Bn256, _, _>(dummy_circuit, rng)?;

  // println!("crs");
  // let crs_file = OpenOptions::new().read(true).open(crs_path)?;
  // let crs = Crs::<Bn256, CrsForMonomialForm>::read(crs_file)?;

  // println!("vk");
  // let _vk = VerificationKey::<
  //   Bn256,
  //   IpaCircuit<Bn256, WrapperChecked<Bn256>, BN256AuxData, RescueChannelGadget<Bn256>>,
  // >::from_setup(&setup, &worker, &crs)?;

  Ok(())
}
