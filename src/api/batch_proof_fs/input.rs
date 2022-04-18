use std::{fs::read_to_string, path::Path, str::FromStr};

use byteorder::{LittleEndian, ReadBytesExt};
use franklin_crypto::{
    babyjubjub::{edwards, JubjubBn256, JubjubEngine, Unknown},
    bellman::{
        kate_commitment::{Crs, CrsForMonomialForm},
        pairing::bn256::{Bn256, Fr},
        plonk::{
            better_better_cs::{
                cs::{Circuit, ProvingAssembly, SetupAssembly, Width4MainGateWithDNext},
                proof::Proof,
                setup::VerificationKey,
            },
            commitments::transcript::keccak_transcript::RollingKeccakTranscript,
        },
        PrimeField, PrimeFieldRepr, ScalarEngine, SynthesisError,
    },
    plonk::circuit::{
        bigint::field::RnsParameters, verifier_circuit::affine_point_wrapper::WrappedAffinePoint,
        Width4WithCustomGates,
    },
};
use verkle_tree::{
    batch_proof_fs::BatchProof,
    ipa_fs::{config::IpaConfig, proof::IpaProof},
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

    use std::{fs::OpenOptions, path::Path};

    use franklin_crypto::{
        babyjubjub::{JubjubBn256, JubjubEngine},
        bellman::{
            pairing::bn256::{Bn256, Fr},
            plonk::{
                better_better_cs::verifier::verify,
                commitments::transcript::keccak_transcript::RollingKeccakTranscript,
            },
        },
        plonk::circuit::{
            bigint::field::RnsParameters,
            verifier_circuit::affine_point_wrapper::without_flag_unchecked::WrapperUnchecked,
        },
    };
    use verkle_tree::{
        batch_proof_fs::BatchProof,
        ipa_fr::utils::test_poly,
        ipa_fs::{
            config::{Committer, IpaConfig},
            transcript::{Bn256Transcript, PoseidonBn256Transcript},
        },
    };

    use crate::api::utils::open_crs_for_log2_of_size;

    use super::BatchProofCircuitInput;

    const CIRCUIT_NAME: &str = "batch_proof_fs";

    fn make_test_input(
        poly_list: &[Vec<<Bn256 as JubjubEngine>::Fs>],
        eval_points: &[usize],
        transcript_params: Fr,
        ipa_conf: &IpaConfig<Bn256>,
    ) -> anyhow::Result<BatchProofCircuitInput> {
        let commitments = poly_list
            .iter()
            .map(|poly| ipa_conf.commit(poly))
            .collect::<Result<Vec<_>, _>>()?;

        let (proof, ys) = BatchProof::<Bn256>::create(
            &commitments,
            poly_list,
            eval_points,
            transcript_params,
            ipa_conf,
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
        let crs = open_crs_for_log2_of_size(23);
        let jubjub_params = &JubjubBn256::new();
        let mut rns_params =
            RnsParameters::<Bn256, <Bn256 as JubjubEngine>::Fs>::new_for_field(68, 110, 4); // TODO: Is this correct?
        let current_bits = rns_params.binary_limbs_bit_widths.last_mut().unwrap();
        let remainder = *current_bits % rns_params.range_check_info.minimal_multiple;
        if remainder != 0 {
            *current_bits += rns_params.range_check_info.minimal_multiple - remainder;
        }

        let eval_points = vec![1];
        let domain_size = 2;
        let ipa_conf = &IpaConfig::<Bn256>::new(domain_size, jubjub_params);

        // Prover view
        let poly = vec![12, 97];
        // let poly = vec![12, 97, 37, 0, 1, 208, 132, 3];
        let padded_poly = test_poly::<<Bn256 as JubjubEngine>::Fs>(&poly, domain_size);
        let prover_transcript = PoseidonBn256Transcript::with_bytes(b"batch_proof");

        // let output = read_field_element_le_from::<Fr>(&[
        //   251, 230, 185, 64, 12, 136, 124, 164, 37, 71, 120, 65, 234, 225, 30, 7, 157, 148, 169, 225,
        //   186, 183, 76, 63, 231, 241, 40, 189, 50, 55, 145, 23,
        // ])
        // .unwrap();
        let circuit_input = make_test_input(
            &[padded_poly],
            &eval_points,
            prover_transcript.clone().into_params(),
            ipa_conf,
        )?;

        let verifier_transcript = PoseidonBn256Transcript::with_bytes(b"batch_proof");

        let is_ok = circuit_input.proof.check(
            &circuit_input.commitments,
            &circuit_input.ys,
            &circuit_input.zs,
            verifier_transcript.clone().into_params(),
            &ipa_conf,
        )?;
        assert!(is_ok);

        let (vk, proof) = circuit_input
            .create_plonk_proof::<WrapperUnchecked<Bn256>>(
                verifier_transcript.into_params(),
                ipa_conf,
                &rns_params,
                crs,
            )
            .unwrap();
        let is_valid = verify::<_, _, RollingKeccakTranscript<Fr>>(&vk, &proof, None)
            .expect("must perform verification");
        assert!(is_valid);

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

        Ok(())
    }

    #[test]
    fn test_batch_proof_fs_circuit_case2() -> Result<(), Box<dyn std::error::Error>> {
        let crs = open_crs_for_log2_of_size(23);
        let jubjub_params = &JubjubBn256::new();
        let mut rns_params =
            RnsParameters::<Bn256, <Bn256 as JubjubEngine>::Fs>::new_for_field(68, 110, 4); // TODO: Is this correct?
        let current_bits = rns_params.binary_limbs_bit_widths.last_mut().unwrap();
        let remainder = *current_bits % rns_params.range_check_info.minimal_multiple;
        if remainder != 0 {
            *current_bits += rns_params.range_check_info.minimal_multiple - remainder;
        }

        let eval_points = vec![1, 0];
        let domain_size = 4;
        let ipa_conf = &IpaConfig::<Bn256>::new(domain_size, jubjub_params);

        // Prover view
        let poly1 = vec![12, 97];
        let poly2 = vec![103, 29];
        let padded_poly1 = test_poly::<<Bn256 as JubjubEngine>::Fs>(&poly1, domain_size);
        let padded_poly2 = test_poly::<<Bn256 as JubjubEngine>::Fs>(&poly2, domain_size);
        let prover_transcript = PoseidonBn256Transcript::with_bytes(b"batch_proof");

        let circuit_input = make_test_input(
            &[padded_poly1, padded_poly2],
            &eval_points,
            prover_transcript.clone().into_params(),
            ipa_conf,
        )?;

        let verifier_transcript = PoseidonBn256Transcript::with_bytes(b"batch_proof");

        // let is_ok = circuit_input.proof.check(
        //     &circuit_input.commitments,
        //     &circuit_input.ys,
        //     &circuit_input.zs,
        //     verifier_transcript.clone().into_params(),
        //     &ipa_conf,
        // )?;
        // assert!(is_ok);

        let (vk, proof) = circuit_input
            .create_plonk_proof::<WrapperUnchecked<Bn256>>(
                verifier_transcript.into_params(),
                ipa_conf,
                &rns_params,
                crs,
            )
            .expect("fail to create PlonK proof");
        let is_valid = verify::<_, _, RollingKeccakTranscript<Fr>>(&vk, &proof, None)
            .expect("must perform verification");
        assert!(is_valid);

        // let proof_path = Path::new("./test_cases")
        //     .join(CIRCUIT_NAME)
        //     .join("proof_case2");
        // let file = OpenOptions::new()
        //     .write(true)
        //     .create(true)
        //     .truncate(true)
        //     .open(proof_path)?;
        // proof.write(file)?;
        // let vk_path = Path::new("./test_cases")
        //     .join(CIRCUIT_NAME)
        //     .join("vk_case2");
        // let file = OpenOptions::new()
        //     .write(true)
        //     .create(true)
        //     .truncate(true)
        //     .open(vk_path)?;
        // vk.write(file)?;

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

    pub fn make_circuit_for_proving<'a, 'b, 'c>(
        &self,
        transcript_params: Fr,
        ipa_conf: &'c IpaConfig<'b, Bn256>,
        rns_params: &'a RnsParameters<Bn256, <Bn256 as JubjubEngine>::Fs>,
    ) -> BatchProofCircuit<'a, 'b, 'c, Bn256>
    where
        'c: 'b,
    {
        BatchProofCircuit::<Bn256> {
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
        }
    }

    // pub fn create_groth16_proof(
    //     &self,
    //     transcript_params: Fr,
    //     ipa_conf: &IpaConfig<Bn256>,
    //     rns_params: &RnsParameters<Bn256, <Bn256 as JubjubEngine>::Fs>,
    //     jubjub_params: &JubjubBn256,
    // ) -> Result<(), SynthesisError> {
    //     let num_rounds = log2_ceil(ipa_conf.get_domain_size()) as usize;
    //     let _dummy_circuit = BatchProofCircuit::<Bn256> {
    //         transcript_params: None,
    //         commitments: vec![None; num_rounds],
    //         proof: OptionIpaProof::with_depth(num_rounds),
    //         d: None,
    //         ys: vec![None; num_rounds],
    //         zs: vec![None; num_rounds],
    //         ipa_conf,
    //         rns_params,
    //         jubjub_params,
    //     };

    //     // let mut dummy_assembly =
    //     //     SetupAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
    //     // dummy_circuit
    //     //     .synthesize(&mut dummy_assembly)
    //     //     .expect("must synthesize");
    //     // dummy_assembly.finalize();

    //     // println!("Checking if satisfied");
    //     // let is_satisfied = dummy_assembly.is_satisfied();
    //     // assert!(is_satisfied, "unsatisfied constraints");

    //     let _rng = &mut rand::thread_rng();
    //     // let setup = generate_random_parameters::<Bn256, _, _>(dummy_circuit, rng)?;

    //     // let vk = &setup.vk;

    //     let _circuit = BatchProofCircuit::<Bn256> {
    //         transcript_params: Some(transcript_params),
    //         commitments: self
    //             .commitments
    //             .iter()
    //             .map(|ci| Some(ci.clone()))
    //             .collect::<Vec<_>>(),
    //         proof: OptionIpaProof::from(self.proof.ipa.clone()),
    //         d: Some(self.proof.d.clone()),
    //         ys: self.ys.iter().map(|&yi| Some(yi)).collect::<Vec<_>>(),
    //         zs: self.zs.iter().map(|&zi| Some(zi)).collect::<Vec<_>>(),
    //         ipa_conf,
    //         rns_params,
    //         jubjub_params,
    //     };

    //     // let mut assembly =
    //     //     ProvingAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
    //     // circuit.synthesize(&mut assembly).expect("must synthesize");
    //     // assembly.finalize();

    //     println!("prove");

    //     // let proof = create_random_proof(circuit, &setup, rng).unwrap();

    //     // assert_eq!(
    //     //     proof.inputs,
    //     //     vec![self.output],
    //     //     "expected input is not equal to one in a circuit"
    //     // );

    //     // let prepared_vk = prepare_verifying_key(&setup.vk);
    //     // let success = verify_proof(&prepared_vk, &proof, &public_input)?;
    //     // if !success {
    //     //     return Err(Error::new(ErrorKind::InvalidData, "verification error").into());
    //     // }

    //     Ok(())
    // }

    #[allow(clippy::type_complexity)]
    pub fn create_plonk_proof<'a, WP: WrappedAffinePoint<'a, Bn256>>(
        &self,
        transcript_params: Fr,
        ipa_conf: &IpaConfig<Bn256>,
        rns_params: &RnsParameters<Bn256, <Bn256 as JubjubEngine>::Fs>,
        crs: Crs<Bn256, CrsForMonomialForm>,
    ) -> Result<
        (
            VerificationKey<Bn256, BatchProofCircuit<Bn256>>,
            Proof<Bn256, BatchProofCircuit<Bn256>>,
        ),
        SynthesisError,
    > {
        let circuit = self.make_circuit_for_proving(transcript_params, ipa_conf, rns_params);
        let _dummy_circuit = BatchProofCircuit::<Bn256>::initialize(ipa_conf, rns_params);

        let mut dummy_assembly =
            SetupAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
        circuit
            .synthesize(&mut dummy_assembly)
            .expect("must synthesize dummy circuit"); // TODO: use `dummy_circuit` instead of `circuit`
        dummy_assembly.finalize();

        // println!("Checking if satisfied");
        // let is_satisfied = dummy_assembly.is_satisfied();
        // assert!(is_satisfied, "unsatisfied constraints");

        let worker = franklin_crypto::bellman::worker::Worker::new();

        let start = std::time::Instant::now();

        let setup = dummy_assembly
            .create_setup::<BatchProofCircuit<Bn256>>(&worker)
            .unwrap();

        println!(
            "reduction ends: {} s",
            start.elapsed().as_millis() as f64 / 1000.0
        );

        let vk =
            VerificationKey::<Bn256, BatchProofCircuit<Bn256>>::from_setup(&setup, &worker, &crs)
                .unwrap();

        let mut assembly =
            ProvingAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
        circuit
            .synthesize(&mut assembly)
            .expect("must synthesize circuit");
        assembly.finalize();

        println!("prove");

        let start = std::time::Instant::now();

        let proof = assembly
            .create_proof::<BatchProofCircuit<Bn256>, RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>>(
                &worker, &setup, &crs, None,
            ).expect("fail to create proof");

        println!(
            "reduction ends: {} s",
            start.elapsed().as_millis() as f64 / 1000.0
        );

        dbg!(&proof.inputs);

        let result = (vk, proof);

        Ok(result)
    }
}
