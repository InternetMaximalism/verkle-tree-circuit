use std::{fs::read_to_string, path::Path, str::FromStr};

use franklin_crypto::bellman::pairing::bn256::Fr;
// use serde::{Deserialize, Serialize};

use crate::circuit::utils::read_point_le;

pub struct CircuitInput {
    pub base_point_x: Option<Fr>,
    pub base_point_y: Option<Fr>,
    pub coefficient: Option<Fr>,
}

impl FromStr for CircuitInput {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        Self::from_bytes(s.as_bytes())
    }
}

impl CircuitInput {
    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let json_str = read_to_string(path)?;

        Self::from_str(&json_str)
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        assert_eq!(bytes.to_vec().len(), 96);
        let reader = &mut std::io::Cursor::new(bytes.to_vec());
        let base_point_x = read_point_le(reader).unwrap();
        let base_point_y = read_point_le(reader).unwrap();
        let coefficient = read_point_le(reader).unwrap();
        let input = Self {
            base_point_x: Some(base_point_x),
            base_point_y: Some(base_point_y),
            coefficient: Some(coefficient),
        };

        Ok(input)
    }

    pub fn default() -> Self {
        Self {
            base_point_x: None,
            base_point_y: None,
            coefficient: None,
        }
    }
}
