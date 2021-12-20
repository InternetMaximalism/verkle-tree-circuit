use std::{fs::read_to_string, path::Path};

use byteorder::{LittleEndian, ReadBytesExt};
use franklin_crypto::bellman::pairing::bn256::{Bn256, Fq, Fr};
use franklin_crypto::bellman::pairing::{CurveAffine, Engine};
// use serde::{Deserialize, Serialize};

use crate::circuit::ipa::proof::IpaProof;
use crate::circuit::utils::read_point;

pub struct CircuitInput {
  pub commitment: Option<<Bn256 as Engine>::G1>,
  pub proof: Option<IpaProof<<Bn256 as Engine>::G1>>,
  pub eval_point: Option<Fr>,
  pub inner_prod: Option<Fr>,
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
    let mut reader = std::io::Cursor::new(bytes.to_vec());
    let commitment_x: Fq = read_point(&mut reader)?;
    let commitment_y: Fq = read_point(&mut reader)?;
    let commitment =
      <Bn256 as Engine>::G1Affine::from_xy_checked(commitment_x, commitment_y)?.into_projective();
    let n = reader.read_u64::<LittleEndian>()?;
    let mut proof_l = vec![];
    for _ in 0..n {
      let lix: Fq = read_point(&mut reader)?;
      let liy: Fq = read_point(&mut reader)?;
      proof_l.push(<Bn256 as Engine>::G1Affine::from_xy_checked(lix, liy)?.into_projective());
    }
    let mut proof_r = vec![];
    for _ in 0..n {
      let rix: Fq = read_point(&mut reader)?;
      let riy: Fq = read_point(&mut reader)?;
      proof_r.push(<Bn256 as Engine>::G1Affine::from_xy_checked(rix, riy)?.into_projective());
    }
    let proof_a: Fr = read_point(&mut reader)?;
    let proof = IpaProof {
      l: proof_l,
      r: proof_r,
      a: proof_a,
    };
    let eval_point: Fr = read_point(&mut reader)?;
    let inner_prod: Fr = read_point(&mut reader)?;
    let input = Self {
      commitment: Some(commitment),
      proof: Some(proof),
      eval_point: Some(eval_point),
      inner_prod: Some(inner_prod),
    };

    Ok(input)
  }

  pub fn default() -> Self {
    Self {
      commitment: None,
      proof: None,
      eval_point: None,
      inner_prod: None,
    }
  }
}
