use std::{fs::read_to_string, path::Path, str::FromStr};

use byteorder::{LittleEndian, ReadBytesExt};
use franklin_crypto::{
    babyjubjub::{edwards, JubjubBn256, JubjubEngine, Unknown},
    bellman::{
        groth16::{create_random_proof, generate_random_parameters, Proof, VerifyingKey},
        pairing::bn256::{Bn256, Fr},
        PrimeField, PrimeFieldRepr, SynthesisError,
    },
    plonk::circuit::bigint::field::RnsParameters,
};
use verkle_tree::{
    batch_proof_fs::BatchProof,
    ipa_fs::{
        config::{Committer, IpaConfig},
        proof::IpaProof,
        utils::log2_ceil,
    },
};
// use serde::{Deserialize, Serialize};

use crate::circuit::{
    batch_proof_fs::BatchProofCircuit, ipa_fs::proof::OptionIpaProof,
    utils::read_field_element_le_from,
};

#[derive(Clone)]
pub struct BatchProofCircuitInput {
    pub commitments: Vec<edwards::Point<Bn256, Unknown>>,
    pub proof: BatchProof<Bn256>,
    pub ys: Vec<<Bn256 as JubjubEngine>::Fs>,
    pub zs: Vec<usize>,
}

#[cfg(test)]
mod batch_proof_fs_api_tests {
    // use std::{fs::OpenOptions, path::Path};

    use franklin_crypto::{
        babyjubjub::{JubjubBn256, JubjubEngine},
        bellman::{
            groth16::{prepare_verifying_key, verify_proof},
            pairing::bn256::{Bn256, Fr},
        },
        plonk::circuit::bigint::field::RnsParameters,
    };
    use verkle_tree::{
        batch_proof_fs::BatchProof,
        ipa_fr::utils::test_poly,
        ipa_fs::{
            config::{Committer, IpaConfig},
            transcript::{Bn256Transcript, PoseidonBn256Transcript},
        },
    };

    use super::BatchProofCircuitInput;

    const CIRCUIT_NAME: &str = "ipa_fs";

    fn make_test_input(
        poly_list: &[Vec<<Bn256 as JubjubEngine>::Fs>],
        eval_points: &[usize],
        transcript_params: Fr,
        jubjub_params: &JubjubBn256,
        ipa_conf: &IpaConfig<Bn256>,
    ) -> anyhow::Result<BatchProofCircuitInput> {
        let commitments = poly_list
            .iter()
            .map(|poly| ipa_conf.commit(poly))
            .collect::<Result<Vec<_>, _>>()?;

        dbg!(commitments.len());
        let (proof, ys) = BatchProof::<Bn256>::create(
            &commitments.clone(),
            poly_list,
            eval_points,
            transcript_params,
            &ipa_conf,
            jubjub_params,
        )?;

        Ok(BatchProofCircuitInput {
            commitments,
            proof,
            ys,
            zs: eval_points.to_vec(),
        })
    }

    #[test]
    fn test_batch_proof_fs_circuit_case1() -> Result<(), Box<dyn std::error::Error>> {
        let jubjub_params = &JubjubBn256::new();
        let rns_params =
            &RnsParameters::<Bn256, <Bn256 as JubjubEngine>::Fs>::new_for_field(68, 110, 4); // TODO: Is this correct?
        let eval_points = vec![1];
        let domain_size = 2;
        let ipa_conf = &IpaConfig::<Bn256>::new(domain_size, jubjub_params);

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
            &[padded_poly],
            &eval_points,
            prover_transcript.clone().into_params(),
            jubjub_params,
            ipa_conf,
        )?;

        // let is_ok = circuit_input.proof.check(
        //     circuit_input.commitment.clone(),
        //     eval_point,
        //     circuit_input.inner_prod,
        //     prover_transcript.clone().into_params(),
        //     &ipa_conf,
        //     jubjub_params,
        // )?;
        // assert!(is_ok);

        circuit_input
            .create_groth16_proof(
                prover_transcript.into_params(),
                ipa_conf,
                rns_params,
                jubjub_params,
            )
            .unwrap();
        // let proof_path = Path::new("./test_cases")
        //     .join(CIRCUIT_NAME)
        //     .join("proof_case1");
        // let file = OpenOptions::new()
        //     .write(true)
        //     .create(true)
        //     .truncate(true)
        //     .open(proof_path)?;
        // proof.write(file)?;
        // let vk_path = Path::new("./test_cases")
        //     .join(CIRCUIT_NAME)
        //     .join("vk_case1");
        // let file = OpenOptions::new()
        //     .write(true)
        //     .create(true)
        //     .truncate(true)
        //     .open(vk_path)?;
        // vk.write(file)?;

        // let public_input = vec![]; // TODO
        // let prepared_vk = prepare_verifying_key(&vk);
        // let success = verify_proof(&prepared_vk, &proof, &public_input)?;
        // assert!(success, "verification error");

        Ok(())
    }
}

impl FromStr for BatchProofCircuitInput {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        Self::from_bytes(s.as_bytes())
    }
}

impl BatchProofCircuitInput {
    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let json_str = read_to_string(path)?;

        Self::from_str(&json_str)
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let jubjub_params = &JubjubBn256::new();
        let reader = &mut std::io::Cursor::new(bytes.to_vec());
        let num_rounds = reader.read_u64::<LittleEndian>()?;

        let mut proof_l = vec![];
        for _ in 0..num_rounds {
            let lix: Fr = read_field_element_le_from(reader)?;
            let liy: Fr = read_field_element_le_from(reader)?;
            let li =
                edwards::Point::get_for_y(liy, lix.into_repr().is_odd(), jubjub_params).unwrap();
            proof_l.push(li);
        }
        let mut proof_r = vec![];
        for _ in 0..num_rounds {
            let rix: Fr = read_field_element_le_from(reader)?;
            let riy: Fr = read_field_element_le_from(reader)?;
            let ri =
                edwards::Point::get_for_y(riy, rix.into_repr().is_odd(), jubjub_params).unwrap();
            proof_r.push(ri);
        }
        let proof_a: <Bn256 as JubjubEngine>::Fs = read_field_element_le_from(reader)?;
        let ipa_proof = IpaProof {
            l: proof_l,
            r: proof_r,
            a: proof_a,
        };
        let dx: Fr = read_field_element_le_from(reader)?;
        let dy: Fr = read_field_element_le_from(reader)?;
        let d = edwards::Point::get_for_y(dy, dx.into_repr().is_odd(), jubjub_params).unwrap();
        let proof = BatchProof { ipa: ipa_proof, d };

        let num_commitments = reader.read_u64::<LittleEndian>()?;
        let mut commitments = vec![];
        for _ in 0..num_commitments {
            let commitment_x: Fr = read_field_element_le_from(reader)?;
            let commitment_y: Fr = read_field_element_le_from(reader)?;
            let commitment = edwards::Point::get_for_y(
                commitment_y,
                commitment_x.into_repr().is_odd(),
                jubjub_params,
            )
            .unwrap();
            commitments.push(commitment);
        }

        let mut ys = vec![];
        for _ in 0..num_commitments {
            let eval_point = read_field_element_le_from(reader)?;
            ys.push(eval_point);
        }

        let z_size_bytes = reader.read_u8()?;
        assert_eq!(z_size_bytes, 1);
        let mut zs = vec![];
        for _ in 0..num_commitments {
            let inner_prod = reader.read_u8()?;
            zs.push(inner_prod as usize);
        }

        let input = Self {
            commitments,
            proof,
            ys,
            zs,
        };

        Ok(input)
    }
}

impl BatchProofCircuitInput {
    pub fn new(
        commitments: Vec<edwards::Point<Bn256, Unknown>>,
        proof: BatchProof<Bn256>,
        ys: Vec<<Bn256 as JubjubEngine>::Fs>,
        zs: Vec<usize>,
    ) -> Self {
        Self {
            commitments,
            proof,
            ys,
            zs,
        }
    }

    pub fn create_groth16_proof(
        &self,
        transcript_params: Fr,
        ipa_conf: &IpaConfig<Bn256>,
        rns_params: &RnsParameters<Bn256, <Bn256 as JubjubEngine>::Fs>,
        jubjub_params: &JubjubBn256,
    ) -> Result<(), SynthesisError> {
        let num_rounds = log2_ceil(ipa_conf.get_domain_size()) as usize;
        let dummy_circuit = BatchProofCircuit::<Bn256> {
            transcript_params: None,
            commitments: vec![None; num_rounds],
            proof: OptionIpaProof::with_depth(num_rounds),
            d: None,
            ys: vec![None; num_rounds],
            zs: vec![None; num_rounds],
            ipa_conf,
            rns_params,
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
        // let setup = generate_random_parameters::<Bn256, _, _>(dummy_circuit, rng)?;

        // let vk = &setup.vk;

        let circuit = BatchProofCircuit::<Bn256> {
            transcript_params: Some(transcript_params),
            commitments: self
                .commitments
                .iter()
                .map(|ci| Some(ci.clone()))
                .collect::<Vec<_>>(),
            proof: OptionIpaProof::from(self.proof.ipa.clone()),
            d: Some(self.proof.d.clone()),
            ys: self.ys.iter().map(|&yi| Some(yi)).collect::<Vec<_>>(),
            zs: self.zs.iter().map(|&zi| Some(zi)).collect::<Vec<_>>(),
            ipa_conf,
            rns_params,
            jubjub_params,
        };

        // let mut assembly =
        //     ProvingAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
        // circuit.synthesize(&mut assembly).expect("must synthesize");
        // assembly.finalize();

        println!("prove");

        // let proof = create_random_proof(circuit, &setup, rng).unwrap();

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

        Ok(())
    }
}
