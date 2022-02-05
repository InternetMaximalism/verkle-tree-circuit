use std::fs::read;
use std::io::{Error, ErrorKind};
use std::{fs::File, path::Path};

use franklin_crypto::bellman::groth16::{prepare_verifying_key, verify_proof, Proof, VerifyingKey};
use franklin_crypto::bellman::pairing::bn256::Bn256;

use crate::circuit::utils::read_field_element_le;

pub fn verify_proof_with_file(
    vk_path: &Path,
    proof_path: &Path,
    public_wires_path: &Path,
) -> anyhow::Result<()> {
    let vk_file = File::open(&vk_path)?;
    let vk = VerifyingKey::<Bn256>::read(&vk_file)?;
    let verifying_key = prepare_verifying_key(&vk);
    let proof_file = File::open(proof_path)?;
    let proof = Proof::<Bn256>::read(&proof_file)?;
    let public_wires_bytes = hex::decode(read(public_wires_path)?)?;
    let reader = &mut std::io::Cursor::new(public_wires_bytes);
    let public_inputs = vec![read_field_element_le(reader)?];

    let success = verify_proof(&verifying_key, &proof, &public_inputs)?;
    if !success {
        return Err(Error::new(ErrorKind::InvalidData, "verification error").into());
    }
    println!("pass verification");

    Ok(())
}
