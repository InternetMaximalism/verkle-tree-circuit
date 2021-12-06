use std::fs::{write, OpenOptions};
use std::marker::PhantomData;
use std::path::Path;

use anyhow::Result;
use franklin_crypto::bellman::groth16::generate_random_parameters;
use franklin_crypto::bellman::pairing::bn256::Bn256;

use crate::api::input::CircuitInput;
use crate::circuit::SampleCircuit;

pub fn generate_random_parameters_with_file(pk_path: &Path, vk_path: &Path) -> Result<()> {
  let dummy_input = CircuitInput::default();
  let circuit = SampleCircuit {
    inputs: dummy_input.inputs,
    _e: PhantomData::<Bn256>,
  };
  let parameters = generate_random_parameters::<Bn256, _, _>(circuit, &mut rand::thread_rng())?;

  let mut verifying_key = Vec::new();
  parameters.vk.write(&mut verifying_key)?;
  write(&vk_path, verifying_key)?;

  let pk_file = OpenOptions::new().write(true).create(true).open(pk_path)?;
  parameters.write(pk_file)?;

  Ok(())
}
