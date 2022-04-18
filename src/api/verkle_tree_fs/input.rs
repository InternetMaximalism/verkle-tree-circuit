#[cfg(test)]
mod batch_proof_api_tests {

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
        bn256_verkle_tree_fs::{proof::VerkleProof, VerkleTreeWith32BytesKeyValue},
        ipa_fs::{
            config::IpaConfig,
            transcript::{Bn256Transcript, PoseidonBn256Transcript},
        },
        verkle_tree::witness::Elements,
    };

    use crate::api::{
        batch_proof_fs::input::BatchProofCircuitInput, utils::open_crs_for_log2_of_size,
    };

    const CIRCUIT_NAME: &str = "verkle_tree_fs";

    #[test]
    fn test_verkle_proof_circuit_case1() -> Result<(), Box<dyn std::error::Error>> {
        let crs = open_crs_for_log2_of_size(23);
        let jubjub_params = &JubjubBn256::new();
        let mut rns_params =
            RnsParameters::<Bn256, <Bn256 as JubjubEngine>::Fs>::new_for_field(68, 110, 4); // TODO: Is this correct?
        let current_bits = rns_params.binary_limbs_bit_widths.last_mut().unwrap();
        let remainder = *current_bits % rns_params.range_check_info.minimal_multiple;
        if remainder != 0 {
            *current_bits += rns_params.range_check_info.minimal_multiple - remainder;
        }

        let domain_size = 4;
        let ipa_conf = &IpaConfig::new(domain_size, jubjub_params);

        // Prover view
        let mut tree = VerkleTreeWith32BytesKeyValue::new(ipa_conf);
        let mut key1 = [0u8; 32];
        key1[0] = 2;
        key1[1] = 2;
        key1[30] = 3;
        key1[31] = 3;
        let mut value1 = [0u8; 32];
        value1[0] = 3;
        value1[15] = 2;
        value1[16] = 2;
        value1[31] = 3;
        tree.insert(key1, value1);
        let mut key2 = [0u8; 32];
        key2[0] = 1;
        key2[1] = 3;
        let mut value2 = [0u8; 32];
        value2[0] = 2;
        tree.insert(key2, value2);
        let keys = [key1];
        let prover_transcript = PoseidonBn256Transcript::with_bytes(b"verkle_tree");

        // let output = read_field_element_le_from::<Fr>(&[
        //   251, 230, 185, 64, 12, 136, 124, 164, 37, 71, 120, 65, 234, 225, 30, 7, 157, 148, 169, 225,
        //   186, 183, 76, 63, 231, 241, 40, 189, 50, 55, 145, 23,
        // ])
        // .unwrap();
        tree.compute_digest().unwrap();

        let (verkle_proof, Elements { zs, ys, .. }) =
            VerkleProof::create(&mut tree, &keys, prover_transcript.clone().into_params()).unwrap();

        let circuit_input = BatchProofCircuitInput {
            commitments: verkle_proof.commitments,
            proof: verkle_proof.multi_proof,
            zs,
            ys,
        };

        let verifier_transcript = PoseidonBn256Transcript::with_bytes(b"verkle_tree");

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
}
