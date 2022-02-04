use std::{fs::read_to_string, path::Path};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CircuitInput {
    pub inputs: [Option<bool>; 2],
}

impl CircuitInput {
    pub fn from_path(_path: &Path) -> anyhow::Result<Self> {
        let json_str = read_to_string(_path)?;

        Self::from_str(&json_str)
    }

    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        let input: Self = serde_json::from_str(s)?;

        Ok(input)
    }

    pub fn default() -> Self {
        Self {
            inputs: [None, None],
        }
    }
}
