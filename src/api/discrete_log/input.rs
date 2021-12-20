use std::{fs::read_to_string, path::Path};

use franklin_crypto::bellman::pairing::bn256::Bn256;
use franklin_crypto::bellman::pairing::{CurveAffine, Engine};
// use serde::{Deserialize, Serialize};

use crate::circuit::utils::read_point;

pub struct CircuitInput {
  pub base_point: Option<<Bn256 as Engine>::G1Affine>,
  pub coefficient: Option<<<Bn256 as Engine>::G1Affine as CurveAffine>::Scalar>,
}

impl CircuitInput {
  pub fn from_path(path: &Path) -> anyhow::Result<Self> {
    let json_str = read_to_string(path)?;

    Self::from_str(&json_str)
  }

  pub fn from_str(s: &str) -> anyhow::Result<Self> {
    Self::from_bytes(s.as_bytes())
  }

  pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
    assert_eq!(bytes.to_vec().len(), 96);
    let mut reader = std::io::Cursor::new(bytes.to_vec());
    let base_x = read_point(&mut reader).unwrap();
    let base_y = read_point(&mut reader).unwrap();
    let base_point = <Bn256 as Engine>::G1Affine::from_xy_checked(base_x, base_y).unwrap();
    let coefficient = read_point(&mut reader).unwrap();
    let input = Self {
      base_point: Some(base_point),
      coefficient: Some(coefficient),
    };

    Ok(input)
  }

  pub fn default() -> Self {
    Self {
      base_point: None,
      coefficient: None,
    }
  }
}
