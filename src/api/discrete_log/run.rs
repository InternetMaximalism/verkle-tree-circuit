use std::io::{Error, ErrorKind};
use std::marker::PhantomData;
use std::path::Path;

use franklin_crypto::alt_babyjubjub::AltJubjubBn256;
use franklin_crypto::bellman::groth16::{
  create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
};
use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use franklin_crypto::bellman::Field;
use franklin_crypto::jubjub::JubjubParams;
use rand;

use crate::circuit::discrete_log::DiscreteLogCircuit;

use super::input::CircuitInput;

pub fn run(circuit_input: CircuitInput) -> anyhow::Result<()> {
  // setup
  println!("setup");
  let dummy_jubjub_params = AltJubjubBn256::new();
  let dummy_input = CircuitInput::default();
  let dummy_circuit = DiscreteLogCircuit::<Bn256> {
    base_point_x: dummy_input.base_point_x,
    base_point_y: dummy_input.base_point_y,
    coefficient: dummy_input.coefficient,
    jubjub_params: dummy_jubjub_params,
    _m: PhantomData,
  };

  println!("create_setup");
  let rng = &mut rand::thread_rng();
  let setup = generate_random_parameters::<Bn256, _, _>(dummy_circuit, rng)?;

  // let vk = setup.vk;

  // prove
  println!("prove");
  let jubjub_params = AltJubjubBn256::new();
  let circuit = DiscreteLogCircuit::<Bn256> {
    base_point_x: circuit_input.base_point_x,
    base_point_y: circuit_input.base_point_y,
    coefficient: circuit_input.coefficient,
    jubjub_params,
    _m: PhantomData,
  };

  println!("create_proof");
  let proof = create_random_proof(circuit, &setup, rng)?;

  // verify
  println!("verify");

  let jubjub_params = AltJubjubBn256::new();
  let mut output_x = circuit_input.base_point_x.unwrap();
  let mut output_y = circuit_input.base_point_y.unwrap();
  let d = jubjub_params.edwards_d();
  let a = jubjub_params.montgomery_a();
  for b in [false, true] {
    if b {
      let tmp_x = output_x;
      let tmp_y = output_y;
      let mut x2 = tmp_x;
      x2.mul_assign(&tmp_x);
      let mut y2 = tmp_y;
      y2.mul_assign(&tmp_y);
      let mut ax2_sub_y2 = x2;
      ax2_sub_y2.mul_assign(a);
      ax2_sub_y2.sub_assign(&y2);
      let mut double_xy = tmp_x;
      double_xy.mul_assign(&tmp_y);
      double_xy.double();
      let mut dx2y2 = x2;
      dx2y2.mul_assign(&y2);
      dx2y2.mul_assign(d);
      output_x = dx2y2;
      output_x.add_assign(&Fr::one());
      output_x.inverse();
      output_x.mul_assign(&double_xy);
      output_y = dx2y2;
      output_y.sub_assign(&Fr::one());
      output_y.inverse();
      output_y.mul_assign(&ax2_sub_y2);
    }
  }
  let public_input = vec![output_x, output_y];
  println!("public_input: {:?}", public_input);
  let prepared_vk = prepare_verifying_key(&setup.vk);
  let success = verify_proof(&prepared_vk, &proof, &public_input)?;
  if !success {
    return Err(Error::new(ErrorKind::InvalidData, "verification error").into());
  }

  Ok(())
}

pub fn run_with_file(input_path: &Path) -> anyhow::Result<()> {
  let circuit_input = CircuitInput::from_path(input_path)?;
  run(circuit_input)
}
