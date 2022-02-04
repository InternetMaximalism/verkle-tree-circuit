use std::{fs::read_to_string, path::Path, str::FromStr};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CircuitInput {
    pub inputs: [Option<bool>; 2],
}

impl CircuitInput {
    pub fn from_path(_path: &Path) -> anyhow::Result<Self> {
        let json_str = read_to_string(_path)?;
        let result = Self::from_str(&json_str)?;

        Ok(result)
    }

    pub fn default() -> Self {
        Self {
            inputs: [None, None],
        }
    }
}

impl FromStr for CircuitInput {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> serde_json::Result<Self> {
        serde_json::from_str(s)
    }
}
