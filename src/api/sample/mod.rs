pub mod input;
pub mod prove;
pub mod run;
pub mod setup;
pub mod verify;

#[test]
fn test_run_sample_circuit() -> Result<(), Box<dyn std::error::Error>> {
    use std::path::Path;

    use self::run::run_with_file;

    let input_path = Path::new("./tests/input.json");
    run_with_file(input_path)?;

    Ok(())
}

#[test]
fn test_setup_prove_verify_sample_circuit() -> Result<(), Box<dyn std::error::Error>> {
    use std::path::Path;

    use self::prove::create_random_proof_with_file;
    use self::setup::generate_random_parameters_with_file;
    use self::verify::verify_proof_with_file;

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
