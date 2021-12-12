use std::marker::PhantomData;
use std::path::Path;

use franklin_crypto::bellman::groth16::{
  create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
};
use franklin_crypto::bellman::pairing::bn256::Bn256;

use crate::circuit::sample::SampleCircuit;

use super::input::CircuitInput;

pub fn run(circuit_input: CircuitInput) -> anyhow::Result<()> {
  // setup
  let dummy_input = CircuitInput::default();
  let circuit = SampleCircuit {
    inputs: dummy_input.inputs,
    _e: PhantomData::<Bn256>,
  };
  let parameters = generate_random_parameters::<Bn256, _, _>(circuit, &mut rand::thread_rng())?;

  // prove
  let circuit = SampleCircuit {
    inputs: circuit_input.inputs,
    _e: PhantomData::<Bn256>,
  };
  let public_wires = circuit.get_public_wires()?;
  let proof = create_random_proof(circuit, &parameters, &mut rand::thread_rng())?;

  // verify
  let vk = parameters.vk;
  let verifying_key = prepare_verifying_key(&vk);
  let success = verify_proof(&verifying_key, &proof, &public_wires).unwrap();
  assert!(success, "verification error");

  Ok(())
}

pub fn run_with_file(input_path: &Path) -> anyhow::Result<()> {
  let circuit_input = CircuitInput::from_path(input_path)?;
  run(circuit_input)
}
