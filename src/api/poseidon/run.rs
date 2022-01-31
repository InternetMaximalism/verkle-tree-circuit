use std::marker::PhantomData;
use std::path::Path;

use bit_vec::{self, BitVec};
use franklin_crypto::alt_babyjubjub::AltJubjubBn256;
use franklin_crypto::bellman::kate_commitment::{Crs, CrsForLagrangeForm, CrsForMonomialForm};
// use franklin_crypto::bellman::groth16::{
//   create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
// };
use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr, FrRepr};
use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::plonk::better_better_cs::cs::{
  Circuit, ConstraintSystem, ProvingAssembly, SetupAssembly, TrivialAssembly,
  Width4MainGateWithDNext,
};
use franklin_crypto::bellman::plonk::better_cs::generator::GeneratorAssembly4WithNextStep as OldActualAssembly;
use franklin_crypto::bellman::plonk::better_cs::prover::ProverAssembly4WithNextStep as OldActualProver;
use franklin_crypto::bellman::plonk::fft::cooley_tukey_ntt::{
  BitReversedOmegas, CTPrecomputations, OmegasInvBitreversed,
};
use franklin_crypto::bellman::plonk::{SetupPolynomialsPrecomputations, VerificationKey};
use franklin_crypto::bellman::{Field, ScalarEngine};
use franklin_crypto::plonk::circuit::bigint::field::RnsParameters;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::aux_data::{
  AuxData, BN256AuxData,
};
use franklin_crypto::plonk::circuit::Width4WithCustomGates;
use rand::{self, Rng};

use crate::circuit::ipa2::utils::{read_point_be, read_point_le};
use crate::circuit::poseidon::PoseidonCircuit;

// use super::input::CircuitInput;
// use super::prover::ProvingAssignment;
// use super::source::DensityTracker;

#[test]
fn test_fr_poseidon_circuit1() -> Result<(), Box<dyn std::error::Error>> {
  // use std::path::Path;

  // let pk_path = Path::new("./tests/ipa/proving_key");
  // let vk_path = Path::new("./tests/ipa/verifying_key");

  let input1 = read_point_le::<Fr>(&[1]).unwrap();
  let input2 = read_point_le::<Fr>(&[2]).unwrap();
  let inputs = vec![input1, input2];
  let output = read_point_le::<Fr>(&[
    251, 230, 185, 64, 12, 136, 124, 164, 37, 71, 120, 65, 234, 225, 30, 7, 157, 148, 169, 225,
    186, 183, 76, 63, 231, 241, 40, 189, 50, 55, 145, 23,
  ])
  .unwrap();
  run(inputs, output).unwrap();

  Ok(())
}

#[test]
fn test_fr_poseidon_circuit2() -> Result<(), Box<dyn std::error::Error>> {
  // use std::path::Path;

  // let pk_path = Path::new("./tests/ipa/proving_key");
  // let vk_path = Path::new("./tests/ipa/verifying_key");

  let mut minus_one = Fr::one();
  minus_one.negate();
  let input1 = minus_one.clone();
  let input2 = minus_one.clone();
  let inputs = vec![input1, input2];
  let output = read_point_le::<Fr>(&[
    139, 216, 105, 49, 182, 238, 242, 238, 71, 120, 119, 185, 65, 172, 205, 105, 49, 66, 1, 26,
    106, 254, 169, 52, 165, 244, 248, 195, 74, 157, 173, 1,
  ])
  .unwrap();
  run(inputs, output).unwrap();

  Ok(())
}

pub fn run(inputs: Vec<Fr>, output: Fr) -> anyhow::Result<()> {
  println!("setup");
  // let dummy_circuit = PoseidonCircuit::<Bn256> {
  //   inputs: vec![None, None],
  //   output: None,
  // };

  let inputs = inputs.iter().map(|&x| Some(x)).collect::<Vec<_>>();
  let output = Some(output);
  let circuit = PoseidonCircuit::<Bn256> { inputs, output };

  println!("Checking if satisfied");
  let mut assembly =
    TrivialAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
  circuit.synthesize(&mut assembly).expect("must synthesize");
  let is_satisfied = assembly.is_satisfied();
  println!("Is satisfied = {}", is_satisfied);

  assert!(is_satisfied, "unsatisfied constraints");

  // use franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;

  let mut assembly =
    ProvingAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
  circuit.synthesize(&mut assembly).expect("must synthesize");
  assembly.finalize();

  let worker = franklin_crypto::bellman::worker::Worker::new();
  // let proof = assembly.create_proof::<_, RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>>(
  //   &worker,
  //   &recursive_circuit_setup,
  //   &crs,
  //   None,
  // )?;

  // assert_eq!(
  //   proof.inputs[0], expected_input,
  //   "expected input is not equal to one in a circuit"
  // );

  Ok(())
}

// pub fn run() -> anyhow::Result<()> {
//   // setup
//   println!("setup");
//   let dummy_circuit = PoseidonCircuit::<Bn256> {
//     inputs: vec![None, None],
//     output: None,
//   };

//   println!("create_setup");
//   // let rng = &mut rand::thread_rng();
//   // let setup = generate_random_parameters::<Bn256, PoseidonCircuit<Bn256>, _>(dummy_circuit, rng)?;
//   let mut dummy_cs = SetupAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
//   dummy_circuit.synthesize(&mut dummy_cs).unwrap();

//   let worker = franklin_crypto::bellman::worker::Worker::new();

//   dummy_cs.finalize();
//   let setup = dummy_cs.create_setup::<PoseidonCircuit<Bn256>>(&worker)?;

//   // let vk = setup.vk;

//   // prove
//   println!("prove");
//   let mut cs = SetupAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();

//   // let rns_params = RnsParameters::<Bn256, <Bn256 as Engine>::Fq>::new_for_field(68, 110, 4);
//   // let rescue_params = Bn256RescueParams::new_checked_2_into_1();
//   // let aux_data = BN256AuxData::new();

//   let point1 = read_point_le::<Fr>(&[1]).unwrap();
//   let point2 = read_point_le::<Fr>(&[2]).unwrap();
//   let inputs = vec![Some(point1), Some(point2)];
//   let output = Some(
//     read_point_le::<Fr>(&[
//       122, 176, 229, 184, 0, 106, 92, 105, 52, 32, 239, 76, 185, 0, 161, 222, 221, 131, 31, 151,
//       70, 90, 168, 249, 232, 221, 240, 148, 67, 227, 101,
//     ])
//     .unwrap(),
//   );
//   println!("output: {:?}", output.unwrap());

//   let circuit = PoseidonCircuit::<Bn256> { inputs, output };
//   // cs.alloc_input(|| Ok(Fr::one())).unwrap();
//   circuit.synthesize(&mut cs).unwrap();

//   // println!("create_proof");
//   // let proof = create_random_proof(circuit, &setup, rng)?;

//   // // verify
//   // println!("verify");

//   // let public_input = vec![circuit.output.unwrap()];
//   // println!("public_input: {:?}", public_input);
//   // let prepared_vk = prepare_verifying_key(&setup.vk);
//   // let success = verify_proof(&prepared_vk, &proof, &public_input)?;
//   // if !success {
//   //   return Err(Error::new(ErrorKind::InvalidData, "verification error").into());
//   // }

//   Ok(())
// }

// pub fn run_with_file(input_path: &Path) -> anyhow::Result<()> {
//   let circuit_input = CircuitInput::from_path(input_path)?;
//   run(circuit_input)
// }
