use std::hash::Hasher;

use franklin_crypto::bellman::pairing::ff::PrimeField;
use franklin_crypto::bellman::pairing::CurveAffine;

use super::utils::{from_bytes_le, to_bytes_le};

pub struct Transcript {
  state: Box<dyn Hasher>,
}

impl Transcript {
  pub fn domain_sep(&mut self, label: &str) {
    self.state.write(label.as_bytes())
  }

  pub fn append_message(&mut self, message: &[u8], label: &str) {
    self.domain_sep(label);
    self.state.write(message);
  }

  pub fn append_scalar<F: PrimeField>(&mut self, scalar: &F, label: &str) {
    self.append_message(&to_bytes_le(scalar), label);
  }

  pub fn append_point<G: CurveAffine>(&mut self, point: &G, label: &str) {
    self.append_message(point.into_compressed().as_ref(), label);
  }

  // Computes a challenge based off of the state of the transcript
  //
  // Hash the transcript state, then reduce the hash modulo the size of the
  // scalar field
  //
  // Note that calling the transcript twice, will yield two different challenges
  pub fn challenge_scalar<F: PrimeField>(&mut self, label: &str) -> F {
    self.domain_sep(label);

    // Reverse the endian so we are using little-endian
    // SetBytes interprets the bytes in Big Endian
    let bytes = self.state.finish().to_le_bytes();
    let tmp = from_bytes_le::<F>(&bytes).unwrap();

    // Clear the state
    // self.state.reset();

    // Add the new challenge to the state
    // Which "summarises" the previous state before we cleared it
    self.append_scalar(&tmp, label);

    // Return the new challenge
    tmp
  }
}
