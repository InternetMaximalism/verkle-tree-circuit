use verkle_circuit::command::invoke_command;
// use verkle_circuit::api::batch_proof_fr::input::batch_proof_api_tests::test_batch_proof_circuit_case1;
// use verkle_circuit::api::verkle_tree::input::batch_proof_api_tests::test_verkle_proof_circuit_case1;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    invoke_command()?;
    // test_batch_proof_circuit_case1()?;
    // test_verkle_proof_circuit_case1()?;

    Ok(())
}
