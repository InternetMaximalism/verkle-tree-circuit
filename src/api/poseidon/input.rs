use std::{
  fs::read_to_string,
  io::{Read, Write},
  path::Path,
};

use byteorder::{ReadBytesExt, WriteBytesExt};
use franklin_crypto::bellman::kate_commitment::{Crs, CrsForMonomialForm};
use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use franklin_crypto::bellman::plonk::better_better_cs::cs::{
  Circuit, ProvingAssembly, SetupAssembly, Width4MainGateWithDNext,
};
use franklin_crypto::bellman::plonk::better_better_cs::proof::Proof;
use franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;
use franklin_crypto::bellman::{ScalarEngine, SynthesisError};
use franklin_crypto::plonk::circuit::Width4WithCustomGates;
use generic_array::{typenum::*, ArrayLength, GenericArray};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::circuit::poseidon::PoseidonCircuit;
// use serde::{Deserialize, Serialize};

use crate::circuit::utils::{read_point_be, read_point_le, write_point_be, write_point_le};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoseidonCircuitInput<N = U2>
where
  N: ArrayLength<Option<Fr>>,
{
  pub(crate) inputs: Vec<Fr>,
  pub(crate) output: Fr,
  _n: std::marker::PhantomData<N>,
}

#[cfg(test)]
mod poseidon_api_tests {
  use std::fs::{read_to_string, File, OpenOptions};
  use std::io::Write;
  use std::path::Path;

  use franklin_crypto::bellman::kate_commitment::{Crs, CrsForMonomialForm};
  use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
  // use franklin_crypto::bellman::plonk::better_better_cs::proof::Proof;
  // use franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
  // use franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;
  use franklin_crypto::bellman::Field;
  // use franklin_crypto::bellman::ScalarEngine;
  use generic_array::typenum::*;

  use crate::circuit::ipa2::utils::read_point_le;
  // use crate::circuit::poseidon::PoseidonCircuit;

  use super::PoseidonCircuitInput;

  fn make_test_input_case1() -> PoseidonCircuitInput<U2> {
    let input1 = crate::circuit::ipa2::utils::read_point_le::<Fr>(&[1]).unwrap();
    let input2 = crate::circuit::ipa2::utils::read_point_le::<Fr>(&[2]).unwrap();
    let inputs = vec![input1, input2];
    let output = crate::circuit::ipa2::utils::read_point_le::<Fr>(&[
      251, 230, 185, 64, 12, 136, 124, 164, 37, 71, 120, 65, 234, 225, 30, 7, 157, 148, 169, 225,
      186, 183, 76, 63, 231, 241, 40, 189, 50, 55, 145, 23,
    ])
    .unwrap();
    let circuit_input = PoseidonCircuitInput {
      inputs,
      output,
      _n: std::marker::PhantomData,
    };

    circuit_input
  }

  fn make_test_input_case2() -> PoseidonCircuitInput<U2> {
    let mut minus_one = Fr::one();
    minus_one.negate();
    let input1 = minus_one.clone();
    let input2 = minus_one.clone();
    let inputs = vec![input1, input2];
    let output = read_point_le::<Fr>(&[
      139, 216, 105, 49, 182, 238, 242, 238, 71, 120, 119, 185, 65, 172, 205, 105, 49, 66, 1, 26,
      106, 254, 169, 52, 165, 244, 248, 195, 74, 157, 173, 1,
    ])
    .unwrap();
    let circuit_input = PoseidonCircuitInput {
      inputs,
      output,
      _n: std::marker::PhantomData,
    };

    circuit_input
  }

  fn open_crs_for_log2_of_size(_log2_n: usize) -> Crs<Bn256, CrsForMonomialForm> {
    let full_path = Path::new("./tests/discrete_log/crs");
    println!("Opening {}", full_path.to_string_lossy());
    let file = File::open(full_path).unwrap();
    let reader = std::io::BufReader::with_capacity(1 << 24, file);
    let crs = Crs::<Bn256, CrsForMonomialForm>::read(reader).unwrap();
    println!("Load {}", full_path.to_string_lossy());

    crs
  }

  fn create_crs_for_log2_of_size(log2_n: usize) -> Crs<Bn256, CrsForMonomialForm> {
    let worker = franklin_crypto::bellman::worker::Worker::new();
    let crs = Crs::<Bn256, CrsForMonomialForm>::crs_42(1 << log2_n, &worker);

    crs
  }

  #[test]
  fn test_crs_serialization() {
    let path = std::env::current_dir().unwrap();
    let path = path.join("tests/poseidon/crs");
    let mut file = File::create(path).unwrap();
    let crs = create_crs_for_log2_of_size(12); // < 4096 constraints (?)
    crs.write(&mut file).expect("must serialize CRS");
  }

  #[test]
  fn test_fr_poseidon_circuit_case1() -> Result<(), Box<dyn std::error::Error>> {
    let crs = open_crs_for_log2_of_size(12);
    let circuit_input = make_test_input_case1();
    let (_vk, _proof) = circuit_input.create_plonk_proof(crs)?;
    let file = OpenOptions::new()
      .write(true)
      .create(true)
      .truncate(true)
      .open("./tests/poseidon/proof_case1")?;
    _proof.write(file)?;
    let file = OpenOptions::new()
      .write(true)
      .create(true)
      .truncate(true)
      .open("./tests/poseidon/vk_case1")?;
    _vk.write(file)?;

    Ok(())
  }

  #[test]
  fn test_fr_poseidon_circuit_case2() -> Result<(), Box<dyn std::error::Error>> {
    let crs = open_crs_for_log2_of_size(12);
    let circuit_input = make_test_input_case2();
    let _proof = circuit_input.create_plonk_proof(crs)?;
    // let file = OpenOptions::new()
    //   .write(true)
    //   .create(true)
    //   .open("./tests/poseidon/proof_case2")?;
    // _proof.write(file)?;

    Ok(())
  }

  // #[test]
  // fn test_fr_poseidon_circuit_verification_case1() -> Result<(), Box<dyn std::error::Error>> {
  //   let file = OpenOptions::new()
  //     .read(true)
  //     .open("./tests/poseidon/proof_case1")?;
  //   let proof = Proof::read(file)?;
  //   let file = OpenOptions::new()
  //     .read(true)
  //     .open("./tests/poseidon/vk_case1")?;
  //   let vk = VerificationKey::read(file)?;
  //   println!("vk: {:?}", vk);

  //   use franklin_crypto::bellman::plonk::better_better_cs::verifier::verify;

  //   // TODO: Is this correct?
  //   let is_valid = verify::<
  //     Bn256,
  //     PoseidonCircuit<Bn256, U2>,
  //     RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>,
  //   >(&vk, &proof, None)?;

  //   assert!(is_valid, "Circuit proof is invalid");

  //   Ok(())
  // }

  #[test]
  fn test_fr_poseidon_circuit_input_read_write() -> Result<(), Box<dyn std::error::Error>> {
    let circuit_input = make_test_input_case1();

    let file_path = "tests/poseidon/public_inputs";
    let path = std::env::current_dir()?;
    let path = path.join(file_path);

    let mut file = OpenOptions::new()
      .write(true)
      .create(true)
      .truncate(true)
      .open(&path)?;
    circuit_input.write_into(&mut file)?;
    println!("write circuit_input into {}", file_path);

    let mut file = OpenOptions::new().read(true).open(&path)?;
    let circuit_input2 = PoseidonCircuitInput::read_from(&mut file)?;
    println!("read circuit_input2 from {}", file_path);

    assert_eq!(circuit_input, circuit_input2);

    Ok(())
  }

  #[test]
  fn test_fr_poseidon_circuit_input_serde_json() -> Result<(), Box<dyn std::error::Error>> {
    let circuit_input: PoseidonCircuitInput<U2> = make_test_input_case1();

    let file_path = "tests/poseidon/public_inputs.json";
    let path = std::env::current_dir()?;
    let path = path.join(file_path);

    let j = serde_json::to_string(&circuit_input)?;
    let mut file = OpenOptions::new()
      .create(true)
      .write(true)
      .truncate(true)
      .open(&path)?;
    write!(file, "{}", j)?;
    println!("write circuit_input into {}", file_path);

    let raw = read_to_string(path)?;
    let circuit_input2: PoseidonCircuitInput<U2> = serde_json::from_str(&raw)?;
    println!("read circuit_input2 from {}", file_path);

    assert_eq!(circuit_input, circuit_input2);

    Ok(())
  }
}

impl<N: ArrayLength<Option<Fr>>> PoseidonCircuitInput<N> {
  pub fn new(inputs: Vec<Fr>, output: Fr) -> Self {
    assert_eq!(inputs.len(), N::to_usize());

    Self {
      inputs,
      output,
      _n: std::marker::PhantomData,
    }
  }

  pub fn get_inputs(&self) -> &Vec<Fr> {
    &self.inputs
  }

  pub fn get_output(&self) -> &Fr {
    &self.output
  }

  pub fn get_width(&self) -> usize {
    N::to_usize()
  }

  pub fn create_plonk_proof(
    &self,
    crs: Crs<Bn256, CrsForMonomialForm>,
  ) -> Result<
    (
      VerificationKey<Bn256, PoseidonCircuit<Bn256, N>>,
      Proof<Bn256, PoseidonCircuit<Bn256, N>>,
    ),
    SynthesisError,
  > {
    // let dummy_circuit = PoseidonCircuit::<Bn256> {
    //   inputs: inputs.iter().map(|&_| None).collect::<Vec<_>>(),
    //   output: None,
    // };

    let circuit = PoseidonCircuit::<Bn256, N> {
      inputs: self
        .inputs
        .iter()
        .map(|&x| Some(x))
        .collect::<GenericArray<Option<Fr>, N>>(),
      output: Some(self.output),
    };

    let mut dummy_assembly =
      SetupAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
    circuit
      .synthesize(&mut dummy_assembly)
      .expect("must synthesize");
    dummy_assembly.finalize();

    // println!("Checking if satisfied");
    // let is_satisfied = dummy_assembly.is_satisfied();
    // assert!(is_satisfied, "unsatisfied constraints");

    let worker = franklin_crypto::bellman::worker::Worker::new();
    let setup = dummy_assembly.create_setup::<PoseidonCircuit<Bn256, N>>(&worker)?;

    let vk =
      VerificationKey::<Bn256, PoseidonCircuit<Bn256, N>>::from_setup(&setup, &worker, &crs)?;

    let mut assembly =
      ProvingAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
    circuit.synthesize(&mut assembly).expect("must synthesize");
    assembly.finalize();

    println!("prove");

    // TODO: Is this correct?
    let proof = assembly
    .create_proof::<PoseidonCircuit<Bn256, N>, RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>>(
      &worker, &setup, &crs, None,
    )?;

    assert_eq!(
      proof.inputs,
      vec![self.output],
      "expected input is not equal to one in a circuit"
    );

    Ok((vk, proof))
  }

  /// `[width, input[0], ..., inputs[t - 2], output]` -> `CircuitInput`
  pub fn read_from<R: Read>(reader: &mut R) -> std::io::Result<Self> {
    let width = reader.read_u8().unwrap();
    assert_eq!(
      width as usize,
      N::to_usize() + 1,
      "invalid length of inputs: expected {}, but {}",
      N::to_usize(),
      width - 1
    );

    let mut inputs = vec![];
    for _ in 1..width {
      let input = read_point_le(reader).unwrap();
      inputs.push(input);
    }
    let output = read_point_le(reader).unwrap();
    let circuit_input = Self {
      inputs,
      output,
      _n: std::marker::PhantomData,
    };

    Ok(circuit_input)
  }

  /// `CircuitInput` -> `[t, input[0], ..., inputs[t - 2], output]`
  pub fn write_into<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
    let width = N::to_usize() + 1;
    assert!(width < 256);

    writer.write_u8(width as u8)?;
    for i in 0..N::to_usize() {
      write_point_le(self.inputs[i], writer)?;
    }
    write_point_le(self.output, writer)?;

    Ok(())
  }

  pub fn from_path(path: &Path) -> std::io::Result<Self> {
    let json_str = read_to_string(path)?;

    Self::from_str(&json_str)
  }

  pub fn from_str(s: &str) -> std::io::Result<Self> {
    Self::read_from(&mut s.as_bytes())
  }
}

impl<N: ArrayLength<Option<Fr>>> Default for PoseidonCircuitInput<N> {
  fn default() -> Self {
    Self {
      inputs: vec![Fr::default(); N::to_usize() - 1],
      output: Fr::default(),
      _n: std::marker::PhantomData,
    }
  }
}

/// `SerializablePoseidonCircuitInput` is needed in the process of serializing `PoseidonCircuitInput`.
/// `PoseidonCircuitInput` is serialized by treating `Fr` as a hex string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SerializablePoseidonCircuitInput {
  inputs: Vec<String>,
  output: String,
}

impl<N: ArrayLength<Option<Fr>>> Serialize for PoseidonCircuitInput<N> {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let mut serializable_inputs = vec![];
    for i in 0..self.inputs.len() {
      let writer = &mut vec![];
      write_point_be(self.inputs[i], writer).unwrap();
      let result = "0x".to_string() + &hex::encode(writer);
      serializable_inputs.push(result);
    }

    let serializable_output = {
      let writer = &mut vec![];
      write_point_be(self.output, writer).unwrap();
      let result = "0x".to_string() + &hex::encode(writer);

      result
    };

    let new_self = SerializablePoseidonCircuitInput {
      inputs: serializable_inputs,
      output: serializable_output,
    };

    new_self.serialize(serializer)
  }
}

impl<'de, N: ArrayLength<Option<Fr>>> Deserialize<'de> for PoseidonCircuitInput<N> {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    let raw = SerializablePoseidonCircuitInput::deserialize(deserializer)?;

    let mut deserialized_inputs = vec![];
    for input in raw.inputs {
      let reader = &mut std::io::Cursor::new(hex::decode(input[2..].as_bytes()).unwrap());
      let input = read_point_be(reader).unwrap();
      deserialized_inputs.push(input);
    }

    let deserialized_output = {
      let reader = &mut std::io::Cursor::new(hex::decode(raw.output[2..].as_bytes()).unwrap());
      read_point_be(reader).unwrap()
    };

    let result = Self {
      inputs: deserialized_inputs,
      output: deserialized_output,
      _n: std::marker::PhantomData,
    };

    Ok(result)
  }
}
