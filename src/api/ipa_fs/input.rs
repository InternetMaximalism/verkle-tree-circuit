use std::{fs::read_to_string, path::Path, str::FromStr};

use byteorder::{LittleEndian, ReadBytesExt};
use franklin_crypto::{
    babyjubjub::{edwards, JubjubBn256, JubjubEngine, Unknown},
    bellman::{
        groth16::{create_random_proof, generate_random_parameters, Proof, VerifyingKey},
        pairing::bn256::{Bn256, Fr},
        PrimeField, PrimeFieldRepr, SynthesisError,
    },
};
use verkle_tree::ipa_fs::{
    config::{Committer, IpaConfig},
    proof::IpaProof,
    utils::log2_ceil,
};
// use serde::{Deserialize, Serialize};

use crate::circuit::{
    ipa_fs::{circuit::IpaCircuit, proof::OptionIpaProof},
    utils::read_field_element_le_from,
};

#[derive(Clone)]
pub struct IpaCircuitInput {
    pub commitment: edwards::Point<Bn256, Unknown>,
    pub proof: IpaProof<Bn256>,
    pub eval_point: <Bn256 as JubjubEngine>::Fs,
    pub inner_prod: <Bn256 as JubjubEngine>::Fs,
}

#[cfg(test)]
mod ipa_api_tests {
    use std::{fs::OpenOptions, path::Path};

    use franklin_crypto::{
        babyjubjub::{JubjubBn256, JubjubEngine},
        bellman::{
            groth16::{prepare_verifying_key, verify_proof},
            pairing::bn256::{Bn256, Fr},
        },
    };
    use verkle_tree::{
        ipa_fr::utils::test_poly,
        ipa_fs::{
            config::{Committer, IpaConfig},
            proof::IpaProof,
            transcript::{Bn256Transcript, PoseidonBn256Transcript},
            utils::read_field_element_le,
        },
    };

    use super::IpaCircuitInput;

    const CIRCUIT_NAME: &str = "ipa_fs";

    fn make_test_input(
        poly: &[<Bn256 as JubjubEngine>::Fs],
        eval_point: <Bn256 as JubjubEngine>::Fs,
        transcript_params: Fr,
        jubjub_params: &JubjubBn256,
        ipa_conf: &IpaConfig<Bn256>,
    ) -> anyhow::Result<IpaCircuitInput> {
        let commitment = ipa_conf.commit(&poly, jubjub_params).unwrap();
        let (proof, ip) = IpaProof::<Bn256>::create(
            commitment.clone(),
            poly,
            eval_point,
            transcript_params,
            &ipa_conf,
            jubjub_params,
        )?;

        Ok(IpaCircuitInput {
            commitment,
            proof,
            eval_point,
            inner_prod: ip,
        })
    }

    #[test]
    fn test_ipa_fs_circuit_case1() -> Result<(), Box<dyn std::error::Error>> {
        let jubjub_params = &JubjubBn256::new();
        let eval_point = read_field_element_le(&123456789u64.to_le_bytes()).unwrap();
        let domain_size = 2;
        let ipa_conf = IpaConfig::<Bn256>::new(domain_size, jubjub_params);

        // Prover view
        let poly = vec![12, 97];
        // let poly = vec![12, 97, 37, 0, 1, 208, 132, 3];
        let padded_poly = test_poly::<<Bn256 as JubjubEngine>::Fs>(&poly, domain_size);
        let prover_transcript = PoseidonBn256Transcript::with_bytes(b"ipa");

        // let output = read_field_element_le_from::<Fr>(&[
        //   251, 230, 185, 64, 12, 136, 124, 164, 37, 71, 120, 65, 234, 225, 30, 7, 157, 148, 169, 225,
        //   186, 183, 76, 63, 231, 241, 40, 189, 50, 55, 145, 23,
        // ])
        // .unwrap();
        let circuit_input = make_test_input(
            &padded_poly,
            eval_point,
            prover_transcript.clone().into_params(),
            jubjub_params,
            &ipa_conf,
        )?;

        let is_ok = circuit_input.proof.check(
            circuit_input.commitment.clone(),
            eval_point,
            circuit_input.inner_prod,
            prover_transcript.clone().into_params(),
            &ipa_conf,
            jubjub_params,
        )?;
        assert!(is_ok);

        let (vk, proof) = circuit_input.create_groth16_proof(
            prover_transcript.into_params(),
            ipa_conf,
            jubjub_params,
        )?;
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

        let public_input = vec![]; // TODO
        let prepared_vk = prepare_verifying_key(&vk);
        let success = verify_proof(&prepared_vk, &proof, &public_input)?;
        assert!(success, "verification error");

        Ok(())
    }
}

impl FromStr for IpaCircuitInput {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        Self::from_bytes(s.as_bytes())
    }
}

impl IpaCircuitInput {
    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let json_str = read_to_string(path)?;

        Self::from_str(&json_str)
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let jubjub_params = &JubjubBn256::new();
        let reader = &mut std::io::Cursor::new(bytes.to_vec());
        let commitment_x: Fr = read_field_element_le_from(reader)?;
        let commitment_y: Fr = read_field_element_le_from(reader)?;
        let commitment = edwards::Point::get_for_y(
            commitment_y,
            commitment_x.into_repr().is_odd(),
            jubjub_params,
        )
        .unwrap();

        let n = reader.read_u64::<LittleEndian>()?;
        let mut proof_l = vec![];
        for _ in 0..n {
            let lix: Fr = read_field_element_le_from(reader)?;
            let liy: Fr = read_field_element_le_from(reader)?;
            let li =
                edwards::Point::get_for_y(liy, lix.into_repr().is_odd(), jubjub_params).unwrap();
            proof_l.push(li);
        }
        let mut proof_r = vec![];
        for _ in 0..n {
            let rix: Fr = read_field_element_le_from(reader)?;
            let riy: Fr = read_field_element_le_from(reader)?;
            let ri =
                edwards::Point::get_for_y(riy, rix.into_repr().is_odd(), jubjub_params).unwrap();
            proof_r.push(ri);
        }
        let proof_a: <Bn256 as JubjubEngine>::Fs = read_field_element_le_from(reader)?;
        let proof = IpaProof {
            l: proof_l,
            r: proof_r,
            a: proof_a,
        };
        let eval_point = read_field_element_le_from(reader)?;
        let inner_prod = read_field_element_le_from(reader)?;
        let input = Self {
            commitment,
            proof,
            eval_point,
            inner_prod,
        };

        Ok(input)
    }
}

impl IpaCircuitInput {
    pub fn new(
        commitment: edwards::Point<Bn256, Unknown>,
        proof: IpaProof<Bn256>,
        eval_point: <Bn256 as JubjubEngine>::Fs,
        inner_prod: <Bn256 as JubjubEngine>::Fs,
    ) -> Self {
        Self {
            commitment,
            proof,
            eval_point,
            inner_prod,
        }
    }

    pub fn create_groth16_proof(
        &self,
        transcript_params: Fr,
        ipa_conf: IpaConfig<Bn256>,
        jubjub_params: &JubjubBn256,
    ) -> Result<(VerifyingKey<Bn256>, Proof<Bn256>), SynthesisError> {
        let num_rounds = log2_ceil(ipa_conf.get_domain_size()) as usize;
        let dummy_circuit = IpaCircuit::<Bn256> {
            transcript_params,
            commitment: None,
            proof: OptionIpaProof::with_depth(num_rounds),
            eval_point: None,
            inner_prod: None,
            ipa_conf: ipa_conf.clone(),
            jubjub_params,
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

        let circuit = IpaCircuit::<Bn256> {
            transcript_params,
            commitment: Some(self.commitment.clone()),
            proof: OptionIpaProof::from(self.proof.clone()),
            eval_point: Some(self.eval_point),
            inner_prod: Some(self.inner_prod),
            ipa_conf,
            jubjub_params,
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
