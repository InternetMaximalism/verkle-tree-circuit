use std::{
    fs::read_to_string,
    io::{Read, Write},
    path::Path,
    str::FromStr,
};

use byteorder::{ReadBytesExt, WriteBytesExt};
use franklin_crypto::bellman::kate_commitment::{Crs, CrsForMonomialForm};
use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use franklin_crypto::bellman::plonk::better_better_cs::cs::{
    Circuit, ProvingAssembly, SetupAssembly, TrivialAssembly, Width4MainGateWithDNext,
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

use crate::circuit::utils::{
    read_field_element_be_from, read_field_element_le_from, write_field_element_be_into,
    write_field_element_le_into,
};

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
    use franklin_crypto::bellman::plonk::better_better_cs::verifier::verify;
    use franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;
    use franklin_crypto::bellman::Field;
    use generic_array::typenum;
    use verkle_tree::ff_utils::bn256_fr::Bn256Fr;
    use verkle_tree::ipa_fr::transcript::{convert_ff_ce_to_ff, convert_ff_to_ff_ce};
    use verkle_tree::ipa_fr::utils::read_field_element_le;
    use verkle_tree::neptune::poseidon::PoseidonConstants;
    use verkle_tree::neptune::Poseidon;
    // use crate::circuit::poseidon::PoseidonCircuit;

    use super::{PoseidonCircuitInput, VkAndProof};

    const CIRCUIT_NAME: &str = "poseidon";

    fn make_test_input(inputs: Vec<Fr>) -> PoseidonCircuitInput<typenum::U2> {
        let preimage = inputs
            .iter()
            .map(|input| convert_ff_ce_to_ff(*input))
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap();
        let constants = PoseidonConstants::new();
        let mut h = Poseidon::<Bn256Fr, typenum::U2>::new_with_preimage(&preimage, &constants);
        let output = convert_ff_to_ff_ce(h.hash()).unwrap();
        println!("output: {:?}", output);

        PoseidonCircuitInput {
            inputs,
            output,
            _n: std::marker::PhantomData,
        }
    }

    fn open_crs_for_log2_of_size(_log2_n: usize) -> Crs<Bn256, CrsForMonomialForm> {
        let full_path = Path::new("./tests").join("crs");
        println!("Opening {}", full_path.to_string_lossy());
        let file = File::open(&full_path).unwrap();
        let reader = std::io::BufReader::with_capacity(1 << 24, file);
        let crs = Crs::<Bn256, CrsForMonomialForm>::read(reader).unwrap();
        println!("Load {}", full_path.to_string_lossy());

        crs
    }

    #[test]
    fn test_fr_poseidon_circuit_case1() -> Result<(), Box<dyn std::error::Error>> {
        // let crs = plonkit::plonk::gen_key_monomial_form(power)?;
        let crs = open_crs_for_log2_of_size(12);
        let input1 = read_field_element_le::<Fr>(&[1]).unwrap();
        let input2 = read_field_element_le::<Fr>(&[2]).unwrap();
        let inputs = vec![input1, input2];
        // let output = read_field_element_le::<Fr>(&[
        //   251, 230, 185, 64, 12, 136, 124, 164, 37, 71, 120, 65, 234, 225, 30, 7, 157, 148, 169, 225,
        //   186, 183, 76, 63, 231, 241, 40, 189, 50, 55, 145, 23,
        // ])
        // .unwrap();
        let circuit_input = make_test_input(inputs);
        let VkAndProof(vk, proof) = circuit_input.create_plonk_proof(crs)?;
        let is_valid = verify::<_, _, RollingKeccakTranscript<Fr>>(&vk, &proof, None)
            .expect("must perform verification");
        assert!(is_valid);

        let proof_path = Path::new("./tests").join(CIRCUIT_NAME).join("proof_case1");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(proof_path)?;
        proof.write(file)?;
        let vk_path = Path::new("./tests").join(CIRCUIT_NAME).join("vk_case1");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(vk_path)?;
        vk.write(file)?;

        Ok(())
    }

    #[test]
    fn test_fr_poseidon_circuit_case2() -> Result<(), Box<dyn std::error::Error>> {
        let crs = open_crs_for_log2_of_size(12);
        let mut minus_one = Fr::one();
        minus_one.negate();
        let input1 = minus_one;
        let input2 = minus_one;
        let inputs = vec![input1, input2];
        // let output = read_field_element_le::<Fr>(&[
        //   139, 216, 105, 49, 182, 238, 242, 238, 71, 120, 119, 185, 65, 172, 205, 105, 49, 66, 1, 26,
        //   106, 254, 169, 52, 165, 244, 248, 195, 74, 157, 173, 1,
        // ])
        // .unwrap();
        let circuit_input = make_test_input(inputs);
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
        let input1 = read_field_element_le::<Fr>(&[1]).unwrap();
        let input2 = read_field_element_le::<Fr>(&[2]).unwrap();
        let inputs = vec![input1, input2];
        let output = read_field_element_le::<Fr>(&[
            251, 230, 185, 64, 12, 136, 124, 164, 37, 71, 120, 65, 234, 225, 30, 7, 157, 148, 169,
            225, 186, 183, 76, 63, 231, 241, 40, 189, 50, 55, 145, 23,
        ])
        .unwrap();
        let circuit_input: PoseidonCircuitInput<typenum::U2> = PoseidonCircuitInput {
            inputs,
            output,
            _n: std::marker::PhantomData,
        };

        let file_path = Path::new("./tests")
            .join(CIRCUIT_NAME)
            .join("public_inputs");
        let path = std::env::current_dir()?;
        let path = path.join(&file_path);

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        circuit_input.write_into(&mut file)?;
        println!("write circuit_input into {:?}", file_path);

        let mut file = OpenOptions::new().read(true).open(&path)?;
        let circuit_input2 = PoseidonCircuitInput::read_from(&mut file)?;
        println!("read circuit_input2 from {:?}", file_path);

        assert_eq!(circuit_input, circuit_input2);

        Ok(())
    }

    #[test]
    fn test_fr_poseidon_circuit_input_serde_json() -> Result<(), Box<dyn std::error::Error>> {
        let input1 = read_field_element_le::<Fr>(&[1]).unwrap();
        let input2 = read_field_element_le::<Fr>(&[2]).unwrap();
        let inputs = vec![input1, input2];
        let output = read_field_element_le::<Fr>(&[
            251, 230, 185, 64, 12, 136, 124, 164, 37, 71, 120, 65, 234, 225, 30, 7, 157, 148, 169,
            225, 186, 183, 76, 63, 231, 241, 40, 189, 50, 55, 145, 23,
        ])
        .unwrap();
        let circuit_input: PoseidonCircuitInput<typenum::U2> = PoseidonCircuitInput {
            inputs,
            output,
            _n: std::marker::PhantomData,
        };

        let file_path = Path::new("./tests")
            .join(CIRCUIT_NAME)
            .join("public_inputs.json");
        let path = std::env::current_dir()?;
        let path = path.join(&file_path);

        let j = serde_json::to_string(&circuit_input)?;
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)?;
        write!(file, "{}", j)?;
        println!("write circuit_input into {:?}", file_path);

        let raw = read_to_string(path)?;
        let circuit_input2: PoseidonCircuitInput<typenum::U2> = serde_json::from_str(&raw)?;
        println!("read circuit_input2 from {:?}", file_path);

        assert_eq!(circuit_input, circuit_input2);

        Ok(())
    }
}

pub struct VkAndProof<N: ArrayLength<Option<Fr>>>(
    pub VerificationKey<Bn256, PoseidonCircuit<Bn256, N>>,
    pub Proof<Bn256, PoseidonCircuit<Bn256, N>>,
);

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
    ) -> Result<VkAndProof<N>, SynthesisError> {
        let dummy_inputs = self
            .inputs
            .iter()
            .map(|&_| None)
            .collect::<GenericArray<_, _>>();
        let dummy_circuit = PoseidonCircuit::<Bn256> {
            inputs: dummy_inputs,
            output: None,
        };

        let circuit = PoseidonCircuit::<Bn256, N> {
            inputs: self
                .inputs
                .iter()
                .map(|&x| Some(x))
                .collect::<GenericArray<_, _>>(),
            output: Some(self.output),
        };

        let mut dummy_assembly =
            SetupAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
        dummy_circuit
            .synthesize(&mut dummy_assembly)
            .expect("must synthesize");
        dummy_assembly.finalize();

        let worker = franklin_crypto::bellman::worker::Worker::new();
        let setup = dummy_assembly.create_setup::<PoseidonCircuit<Bn256, N>>(&worker)?;

        let vk =
            VerificationKey::<Bn256, PoseidonCircuit<Bn256, N>>::from_setup(&setup, &worker, &crs)?;

        println!("Checking if satisfied");
        let mut trivial_assembly =
            TrivialAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
        circuit
            .synthesize(&mut trivial_assembly)
            .expect("must synthesize");
        if !trivial_assembly.is_satisfied() {
            return Err(SynthesisError::Unsatisfiable);
        }

        println!("prove");

        let mut assembly =
            ProvingAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
        circuit.synthesize(&mut assembly).expect("must synthesize");
        assembly.finalize();

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

        let result = VkAndProof(vk, proof);

        Ok(result)
    }

    /// `[width, input[0], ..., inputs[t - 2], output]` -> `CircuitInput`
    pub fn read_from<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let width = reader.read_u8()?;
        assert_eq!(
            width as usize,
            N::to_usize() + 1,
            "invalid length of inputs: expected {}, but {}",
            N::to_usize(),
            width - 1
        );

        let mut inputs = vec![];
        for _ in 1..width {
            let input = read_field_element_le_from(reader)?;
            inputs.push(input);
        }
        let output = read_field_element_le_from(reader)?;
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
            write_field_element_le_into(self.inputs[i], writer)?;
        }
        write_field_element_le_into(self.output, writer)?;

        Ok(())
    }

    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let json_str = read_to_string(path)?;

        Self::from_str(&json_str)
    }
}

impl<N: ArrayLength<Option<Fr>>> FromStr for PoseidonCircuitInput<N> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
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
            write_field_element_be_into(self.inputs[i], writer).unwrap();
            let result = "0x".to_string() + &hex::encode(writer);
            serializable_inputs.push(result);
        }

        let serializable_output = {
            let writer = &mut vec![];
            write_field_element_be_into(self.output, writer).unwrap();

            "0x".to_string() + &hex::encode(writer)
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
            let input = read_field_element_be_from(reader).unwrap();
            deserialized_inputs.push(input);
        }

        let deserialized_output = {
            let reader =
                &mut std::io::Cursor::new(hex::decode(raw.output[2..].as_bytes()).unwrap());
            read_field_element_be_from(reader).unwrap()
        };

        let result = Self {
            inputs: deserialized_inputs,
            output: deserialized_output,
            _n: std::marker::PhantomData,
        };

        Ok(result)
    }
}
