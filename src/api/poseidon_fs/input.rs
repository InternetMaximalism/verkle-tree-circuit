use franklin_crypto::bellman::{
    groth16::{create_random_proof, generate_random_parameters, Proof, VerifyingKey},
    pairing::bn256::{Bn256, Fr},
    SynthesisError,
};
use generic_array::{typenum::*, ArrayLength, GenericArray};
// use serde::{Deserialize, Serialize};

use crate::circuit::poseidon_fs::PoseidonCircuit;

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
mod ipa_api_tests {
    use std::{fs::OpenOptions, path::Path};

    use franklin_crypto::bellman::{
        groth16::{prepare_verifying_key, verify_proof},
        pairing::bn256::Fr,
    };
    use generic_array::typenum;
    use verkle_tree::ff_utils::bn256_fr::Bn256Fr;
    use verkle_tree::ipa_fr::transcript::{convert_ff_ce_to_ff, convert_ff_to_ff_ce};
    use verkle_tree::ipa_fs::utils::read_field_element_le;
    use verkle_tree::neptune::poseidon::PoseidonConstants;
    use verkle_tree::neptune::Poseidon;

    use super::PoseidonCircuitInput;

    const CIRCUIT_NAME: &str = "ipa_fs";

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

    #[test]
    fn test_ipa_fs_circuit_case1() -> Result<(), Box<dyn std::error::Error>> {
        let input1 = read_field_element_le::<Fr>(&[1]).unwrap();
        let input2 = read_field_element_le::<Fr>(&[2]).unwrap();
        let inputs = vec![input1, input2];

        // Prover's view
        let circuit_input = make_test_input(inputs);

        let (vk, proof) = circuit_input.create_groth16_proof()?;

        let proof_path = Path::new("./test_cases")
            .join(CIRCUIT_NAME)
            .join("proof_case1");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(proof_path)?;
        proof.write(file)?;
        let vk_path = Path::new("./test_cases")
            .join(CIRCUIT_NAME)
            .join("vk_case1");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(vk_path)?;
        vk.write(file)?;

        // Verifier's view
        let public_input = vec![circuit_input.output];
        let prepared_vk = prepare_verifying_key(&vk);
        let success = verify_proof(&prepared_vk, &proof, &public_input)?;
        assert!(success, "verification error");

        Ok(())
    }
}

// impl FromStr for PoseidonCircuitInput {
//     type Err = anyhow::Error;

//     fn from_str(s: &str) -> anyhow::Result<Self> {
//         Self::from_bytes(s.as_bytes())
//     }
// }

// impl PoseidonCircuitInput {
//     pub fn from_path(path: &Path) -> anyhow::Result<Self> {
//         let json_str = read_to_string(path)?;

//         Self::from_str(&json_str)
//     }

//     pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
//         let jubjub_params = &JubjubBn256::new();
//         let reader = &mut std::io::Cursor::new(bytes.to_vec());
//         let commitment_x: Fr = read_field_element_le_from(reader)?;
//         let commitment_y: Fr = read_field_element_le_from(reader)?;
//         let commitment = edwards::Point::get_for_y(
//             commitment_y,
//             commitment_x.into_repr().is_odd(),
//             jubjub_params,
//         )
//         .unwrap();

//         let n = reader.read_u64::<LittleEndian>()?;
//         let mut proof_l = vec![];
//         for _ in 0..n {
//             let lix: Fr = read_field_element_le_from(reader)?;
//             let liy: Fr = read_field_element_le_from(reader)?;
//             let li =
//                 edwards::Point::get_for_y(liy, lix.into_repr().is_odd(), jubjub_params).unwrap();
//             proof_l.push(li);
//         }
//         let mut proof_r = vec![];
//         for _ in 0..n {
//             let rix: Fr = read_field_element_le_from(reader)?;
//             let riy: Fr = read_field_element_le_from(reader)?;
//             let ri =
//                 edwards::Point::get_for_y(riy, rix.into_repr().is_odd(), jubjub_params).unwrap();
//             proof_r.push(ri);
//         }
//         let proof_a: <Bn256 as JubjubEngine>::Fs = read_field_element_le_from(reader)?;
//         let proof = IpaProof {
//             l: proof_l,
//             r: proof_r,
//             a: proof_a,
//         };
//         let eval_point = read_field_element_le_from(reader)?;
//         let inner_prod = read_field_element_le_from(reader)?;
//         let input = Self {
//             commitment,
//             proof,
//             eval_point,
//             inner_prod,
//         };

//         Ok(input)
//     }
// }

impl<N: ArrayLength<Option<Fr>>> PoseidonCircuitInput<N> {
    pub fn new(inputs: Vec<Fr>, output: Fr) -> Self {
        assert_eq!(inputs.len(), N::to_usize());

        Self {
            inputs,
            output,
            _n: std::marker::PhantomData,
        }
    }

    pub fn create_groth16_proof(
        &self,
    ) -> Result<(VerifyingKey<Bn256>, Proof<Bn256>), SynthesisError> {
        let dummy_inputs = self
            .inputs
            .iter()
            .map(|&_| None)
            .collect::<GenericArray<_, _>>();
        let dummy_circuit = PoseidonCircuit::<Bn256> {
            inputs: dummy_inputs,
            output: None,
        };

        // let mut dummy_assembly =
        //     SetupAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
        // dummy_circuit
        //     .synthesize(&mut dummy_assembly)
        //     .expect("must synthesize");
        // dummy_assembly.finalize();

        // println!("Checking if satisfied");
        // let is_satisfied = dummy_assembly.is_satisfied();
        // assert!(is_satisfied, "unsatisfied constraints");

        let rng = &mut rand::thread_rng();
        let setup = generate_random_parameters::<Bn256, _, _>(dummy_circuit, rng)?;

        let vk = &setup.vk;

        let circuit = PoseidonCircuit::<Bn256> {
            inputs: self
                .inputs
                .iter()
                .map(|&x| Some(x))
                .collect::<GenericArray<_, _>>(),
            output: Some(self.output),
        };

        // let mut assembly =
        //     ProvingAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
        // circuit.synthesize(&mut assembly).expect("must synthesize");
        // assembly.finalize();

        println!("prove");

        let proof = create_random_proof(circuit, &setup, rng)?;

        // assert_eq!(
        //     proof.inputs,
        //     vec![self.output],
        //     "expected input is not equal to one in a circuit"
        // );

        // let prepared_vk = prepare_verifying_key(&setup.vk);
        // let success = verify_proof(&prepared_vk, &proof, &public_input)?;
        // if !success {
        //     return Err(Error::new(ErrorKind::InvalidData, "verification error").into());
        // }

        Ok((vk.clone(), proof))
    }
}
