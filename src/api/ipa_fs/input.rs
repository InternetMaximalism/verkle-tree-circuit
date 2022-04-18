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
use verkle_tree::ipa_fs::{config::IpaConfig, proof::IpaProof};
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
        ipa_fr::utils::test_poly,
        ipa_fs::{
            config::{Committer, IpaConfig},
            proof::IpaProof,
            transcript::{Bn256Transcript, PoseidonBn256Transcript},
            utils::read_field_element_le,
        },
    };

    use crate::api::utils::open_crs_for_log2_of_size;

    use super::IpaCircuitInput;

    const CIRCUIT_NAME: &str = "ipa_fs";

    fn make_test_input(
        poly: &[<Bn256 as JubjubEngine>::Fs],
        eval_point: <Bn256 as JubjubEngine>::Fs,
        transcript_params: Fr,
        ipa_conf: &IpaConfig<Bn256>,
    ) -> anyhow::Result<IpaCircuitInput> {
        let commitment = ipa_conf.commit(poly).unwrap();
        let (proof, ip) = IpaProof::<Bn256>::create(
            commitment.clone(),
            poly,
            eval_point,
            transcript_params,
            ipa_conf,
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
        let crs = open_crs_for_log2_of_size(23);
        let jubjub_params = &JubjubBn256::new();
        let mut rns_params =
            RnsParameters::<Bn256, <Bn256 as JubjubEngine>::Fs>::new_for_field(68, 110, 4);
        let current_bits = rns_params.binary_limbs_bit_widths.last_mut().unwrap();
        let remainder = *current_bits % rns_params.range_check_info.minimal_multiple;
        if remainder != 0 {
            *current_bits += rns_params.range_check_info.minimal_multiple - remainder;
        }

        let eval_point: <Bn256 as JubjubEngine>::Fs =
            read_field_element_le(&123456789u64.to_le_bytes()).unwrap();
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
            &padded_poly,
            eval_point,
            prover_transcript.into_params(),
            ipa_conf,
        )?;

        let verifier_transcript = PoseidonBn256Transcript::with_bytes(b"ipa");
        // let is_ok = circuit_input.proof.check(
        //     circuit_input.commitment.clone(),
        //     circuit_input.eval_point,
        //     circuit_input.inner_prod,
        //     verifier_transcript.clone().into_params(),
        //     &ipa_conf,
        // )?;
        // assert!(is_ok);

        let (vk, proof) = circuit_input.create_plonk_proof::<WrapperUnchecked<'_, Bn256>>(
            verifier_transcript.into_params(),
            ipa_conf,
            &rns_params,
            crs,
        )?;

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

    pub fn make_circuit_for_proving<'a, 'b, 'c>(
        &self,
        transcript_params: Fr,
        ipa_conf: &'c IpaConfig<'b, Bn256>,
        rns_params: &'a RnsParameters<Bn256, <Bn256 as JubjubEngine>::Fs>,
    ) -> IpaCircuit<'a, 'b, 'c, Bn256>
    where
        'c: 'b,
    {
        IpaCircuit::<Bn256> {
            transcript_params: Some(transcript_params),
            commitment: Some(self.commitment.clone()),
            proof: OptionIpaProof::from(self.proof.clone()),
            eval_point: Some(self.eval_point),
            inner_prod: Some(self.inner_prod),
            ipa_conf,
            rns_params,
        }
    }

    // pub fn create_groth16_proof(
    //     &self,
    //     transcript_params: Fr,
    //     ipa_conf: &IpaConfig<Bn256>,
    //     jubjub_params: &JubjubBn256,
    //     rns_params: &RnsParameters<Bn256, <Bn256 as JubjubEngine>::Fs>,
    // ) -> Result<(VerifyingKey<Bn256>, Proof<Bn256>), SynthesisError> {
    //     let num_rounds = log2_ceil(ipa_conf.get_domain_size()) as usize;
    //     let dummy_circuit = IpaCircuit::<Bn256> {
    //         transcript_params: None,
    //         commitment: None,
    //         proof: OptionIpaProof::with_depth(num_rounds),
    //         eval_point: None,
    //         inner_prod: None,
    //         ipa_conf,
    //         jubjub_params,
    //         rns_params,
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

    //     let rng = &mut rand::thread_rng();
    //     let setup = generate_random_parameters::<Bn256, _, _>(dummy_circuit, rng)?;

    //     let vk = &setup.vk;

    //     let circuit = IpaCircuit::<Bn256> {
    //         transcript_params: Some(transcript_params),
    //         commitment: Some(self.commitment.clone()),
    //         proof: OptionIpaProof::from(self.proof.clone()),
    //         eval_point: Some(self.eval_point),
    //         inner_prod: Some(self.inner_prod),
    //         ipa_conf,
    //         jubjub_params,
    //         rns_params,
    //     };

    //     // let mut assembly =
    //     //     ProvingAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
    //     // circuit.synthesize(&mut assembly).expect("must synthesize");
    //     // assembly.finalize();

    //     println!("prove");

    //     let proof = create_random_proof(circuit, &setup, rng)?;

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

    //     Ok((vk.clone(), proof))
    // }

    #[allow(clippy::type_complexity)]
    pub fn create_plonk_proof<'a, WP: WrappedAffinePoint<'a, Bn256>>(
        &self,
        transcript_params: Fr,
        ipa_conf: &IpaConfig<Bn256>,
        rns_params: &'a RnsParameters<Bn256, <Bn256 as JubjubEngine>::Fs>,
        crs: Crs<Bn256, CrsForMonomialForm>,
    ) -> Result<
        (
            VerificationKey<Bn256, IpaCircuit<Bn256>>,
            Proof<Bn256, IpaCircuit<Bn256>>,
        ),
        SynthesisError,
    > {
        let dummy_circuit = IpaCircuit::<Bn256>::initialize(ipa_conf, rns_params);
        // let dummy_circuit = {
        //     transcript_params: None,
        //     commitment: None,
        //     proof: OptionIpaProof::from(self.proof.clone()),
        //     eval_point: None,
        //     inner_prod: None,
        //     ipa_conf,
        //     jubjub_params,
        //     rns_params,
        // };

        let mut dummy_assembly =
            SetupAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
        dummy_circuit
            .synthesize(&mut dummy_assembly)
            .expect("must synthesize");
        dummy_assembly.finalize();

        // println!("Checking if satisfied");
        // let is_satisfied = dummy_assembly.is_satisfied();
        // assert!(is_satisfied, "unsatisfied constraints");

        let worker = franklin_crypto::bellman::worker::Worker::new();
        let setup = dummy_assembly.create_setup::<IpaCircuit<Bn256>>(&worker)?;

        let vk = VerificationKey::<Bn256, IpaCircuit<Bn256>>::from_setup(&setup, &worker, &crs)?;

        let circuit = self.make_circuit_for_proving(transcript_params, ipa_conf, rns_params);
        // let circuit = IpaCircuit::<Bn256> {
        //     transcript_params: Some(transcript_params),
        //     commitment: Some(self.commitment.clone()),
        //     proof: OptionIpaProof::from(self.proof.clone()),
        //     eval_point: Some(self.eval_point),
        //     inner_prod: Some(self.inner_prod),
        //     ipa_conf,
        //     jubjub_params,
        //     rns_params,
        // };

        let mut assembly =
            ProvingAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
        circuit.synthesize(&mut assembly).expect("must synthesize");
        assembly.finalize();

        println!("prove");

        let proof = assembly
            .create_proof::<IpaCircuit<Bn256>, RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>>(
                &worker, &setup, &crs, None,
            )?;

        // assert_eq!(
        //     proof.inputs,
        //     vec![self.output],
        //     "expected input is not equal to one in a circuit"
        // );

        let result = (vk, proof);

        Ok(result)
    }
}
