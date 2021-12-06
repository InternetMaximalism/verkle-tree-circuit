use std::{fs::read_to_string, path::Path};

use anyhow::Result;
use franklin_crypto::bellman::pairing::ff::{Field, PrimeField};
use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::circuit::multipack::bytes_to_bits_le;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CircuitInput {
  pub inputs: [Option<bool>; 2],
}

impl CircuitInput {
  pub fn from_path(_path: &Path) -> Result<Self> {
    let json_str = read_to_string(_path)?;

    Self::from_str(&json_str)
  }

  pub fn from_str(_str: &str) -> Result<Self> {
    let input: Self = serde_json::from_str(_str)?;

    Ok(input)
  }

  pub fn default() -> Self {
    Self {
      inputs: [None, None],
    }
  }
}

pub fn decode_public_wires<E: Engine>(bytes: &[u8]) -> Vec<E::Fr> {
  let capacity_bytes = (E::Fr::CAPACITY - 1) / 8 + 1;
  let mut result: Vec<E::Fr> = vec![];

  for split_bytes in bytes.chunks(capacity_bytes as usize) {
    let mut cur = E::Fr::zero();
    let mut coeff = E::Fr::one();

    for bit in bytes_to_bits_le(split_bytes) {
      if bit {
        cur.add_assign(&coeff);
      }

      coeff.double();
    }

    result.push(cur);
  }

  result
}
