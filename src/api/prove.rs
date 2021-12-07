use std::fs::{File, OpenOptions};
use std::io::Write;
use std::marker::PhantomData;
use std::path::Path;

use anyhow::Result;
use franklin_crypto::bellman::groth16::{create_random_proof, Parameters};
use franklin_crypto::bellman::pairing::bn256::Bn256;

use crate::api::input::CircuitInput;
use crate::circuit::sample::SampleCircuit;

pub fn create_random_proof_with_file(
  pk_path: &Path,
  input_path: &Path,
  proof_path: &Path,
  public_wires_path: &Path,
) -> Result<()> {
  let circuit_input = CircuitInput::from_path(input_path)?;
  let proving_key = File::open(&pk_path)?;
  let parameters = Parameters::<Bn256>::read(&proving_key, true)?;
  let circuit = SampleCircuit {
    inputs: circuit_input.inputs,
    _e: PhantomData::<Bn256>,
  };

  let public_wires_bytes = circuit.get_public_wires()?;
  let mut public_wires_file = OpenOptions::new()
    .write(true)
    .create(true)
    .open(public_wires_path)?;
  public_wires_file.write(hex::encode(&public_wires_bytes).as_bytes())?;

  let proof = create_random_proof(circuit, &parameters, &mut rand::thread_rng())?;
  let proof_file = OpenOptions::new()
    .write(true)
    .create(true)
    .open(proof_path)?;
  proof.write(proof_file)?;

  Ok(())
}
