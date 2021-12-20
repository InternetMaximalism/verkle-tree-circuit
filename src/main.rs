use verkle_circuit::command::invoke_command;

#[test]
fn test_run_sample_circuit() -> Result<(), Box<dyn std::error::Error>> {
  use std::path::Path;

  use verkle_circuit::api::sample::run::run_with_file;

  let input_path = Path::new("./tests/input.json");
  run_with_file(input_path)?;

  Ok(())
}

#[test]
fn test_setup_prove_verify_sample_circuit() -> Result<(), Box<dyn std::error::Error>> {
  use std::path::Path;

  use verkle_circuit::api::sample::prove::create_random_proof_with_file;
  use verkle_circuit::api::sample::setup::generate_random_parameters_with_file;
  use verkle_circuit::api::sample::verify::verify_proof_with_file;

  let input_path = Path::new("./tests/input.json");
  let pk_path = Path::new("./tests/proving_key");
  let vk_path = Path::new("./tests/verifying_key");
  let proof_path = Path::new("./tests/proof");
  let public_wires_path = Path::new("./tests/public_wires.txt");
  generate_random_parameters_with_file(pk_path, vk_path)?;
  create_random_proof_with_file(pk_path, input_path, proof_path, public_wires_path)?;
  verify_proof_with_file(vk_path, proof_path, public_wires_path)?;

  Ok(())
}

#[test]
fn test_discrete_log_circuit() -> Result<(), Box<dyn std::error::Error>> {
  use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr, FrRepr};
  use franklin_crypto::bellman::pairing::ff::PrimeField;
  use franklin_crypto::bellman::pairing::{CurveAffine, Engine};
  use verkle_circuit::api::discrete_log::input::CircuitInput;
  use verkle_circuit::api::discrete_log::run::run;

  let base_point = <<Bn256 as Engine>::G1Affine as CurveAffine>::one();
  let coefficient = Fr::from_repr(FrRepr([0u64, 1, 0, 0]))?;
  let circuit_input = CircuitInput {
    base_point: Some(base_point),
    coefficient: Some(coefficient),
  };
  run(circuit_input)?;

  Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  invoke_command()?;

  Ok(())
}
