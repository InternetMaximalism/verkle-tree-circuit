use std::fs::read;
use std::io::{Error, ErrorKind};
use std::{fs::File, path::Path};

use anyhow::Result;
use franklin_crypto::bellman::groth16::{prepare_verifying_key, verify_proof, Proof, VerifyingKey};
use franklin_crypto::bellman::pairing::bn256::Bn256;

use crate::api::input::decode_public_wires;

pub fn verify_proof_with_file(
  vk_path: &Path,
  proof_path: &Path,
  public_wires_path: &Path,
) -> Result<()> {
  let vk_file = File::open(&vk_path)?;
  let vk = VerifyingKey::<Bn256>::read(&vk_file)?;
  let verifying_key = prepare_verifying_key(&vk);
  let proof_file = File::open(proof_path)?;
  let proof = Proof::<Bn256>::read(&proof_file)?;
  let public_wires_bytes = read(public_wires_path)?;
  let public_inputs = decode_public_wires::<Bn256>(&hex::decode(&public_wires_bytes)?);

  let success = verify_proof(&verifying_key, &proof, &public_inputs)?;
  if !success {
    return Err(Error::new(ErrorKind::InvalidData, "verification error").into());
  }

  Ok(())
}
