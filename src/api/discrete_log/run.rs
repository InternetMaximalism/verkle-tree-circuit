use std::io::{Error, ErrorKind};
use std::marker::PhantomData;
use std::path::Path;

use franklin_crypto::babyjubjub::{edwards, JubjubBn256, Unknown};
use franklin_crypto::bellman::groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
};
use franklin_crypto::bellman::pairing::bn256::Bn256;
use franklin_crypto::bellman::{PrimeField, PrimeFieldRepr};
use rand;

use crate::circuit::discrete_log::DiscreteLogCircuit;

use super::input::CircuitInput;

pub fn run(circuit_input: CircuitInput) -> anyhow::Result<()> {
    // setup
    println!("setup");
    let dummy_jubjub_params = JubjubBn256::new();
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

    // prove
    println!("prove");
    let jubjub_params = JubjubBn256::new();
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

    let jubjub_params = JubjubBn256::new();
    let base_point_x = circuit_input.base_point_x.unwrap();
    let base_point_y = circuit_input.base_point_y.unwrap();
    let base_point = edwards::Point::<Bn256, Unknown>::get_for_y(
        base_point_y,
        base_point_x.into_repr().is_odd(),
        &jubjub_params,
    )
    .unwrap();
    let output = base_point.mul(circuit_input.coefficient.unwrap(), &jubjub_params);
    let (output_x, output_y) = output.into_xy();
    let public_input = vec![output_x, output_y];
    dbg!(&public_input);
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
