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
    use franklin_crypto::bellman::pairing::bn256::{Fr, FrRepr};
    use franklin_crypto::bellman::pairing::ff::PrimeField;
    use verkle_circuit::api::discrete_log::input::CircuitInput;
    use verkle_circuit::api::discrete_log::run::run;

    let base_point_x = Fr::from_repr(FrRepr([
        0x2893f3f6bb957051u64,
        0x2ab8d8010534e0b6,
        0x4eacb2e09d6277c1,
        0x0bb77a6ad63e739b,
    ]))?;
    let base_point_y = Fr::from_repr(FrRepr([
        0x4b3c257a872d7d8bu64,
        0xfce0051fb9e13377,
        0x25572e1cd16bf9ed,
        0x25797203f7a0b249,
    ]))?;
    let coefficient = Fr::from_repr(FrRepr([4u64, 3, 2, 1]))?;
    let circuit_input = CircuitInput {
        base_point_x: Some(base_point_x),
        base_point_y: Some(base_point_y),
        coefficient: Some(coefficient),
    };
    run(circuit_input)?;

    Ok(())
}

#[test]
fn test_ipa_circuit() -> Result<(), Box<dyn std::error::Error>> {
    use std::path::Path;

    use verkle_circuit::api::ipa::setup::generate_random_parameters_with_file;

    let pk_path = Path::new("./tests/ipa/proving_key");
    let vk_path = Path::new("./tests/ipa/verifying_key");
    // let size = 2usize.pow(21); // 2097152
    // make_crs_with_file::<franklin_crypto::bellman::pairing::bn256::Bn256>(crs_path, size)?;
    generate_random_parameters_with_file(pk_path, vk_path)?;

    Ok(())
}

// #[test]
// fn test_batch_proof_circuit() -> Result<(), Box<dyn std::error::Error>> {
//   use std::path::Path;

//   use verkle_circuit::api::batch_proof::setup::generate_random_parameters_with_file;

//   let pk_path = Path::new("./tests/batch_proof/proving_key");
//   let vk_path = Path::new("./tests/batch_proof/verifying_key");
//   // let size = 2usize.pow(21); // 2097152
//   // make_crs_with_file::<franklin_crypto::bellman::pairing::bn256::Bn256>(crs_path, size)?;
//   generate_random_parameters_with_file(pk_path, vk_path)?;

//   Ok(())
// }

fn main() -> Result<(), Box<dyn std::error::Error>> {
    invoke_command()?;

    Ok(())
}
