#[cfg(test)]
mod batch_proof_api_tests {
    use std::fs::OpenOptions;
    use std::path::Path;

    use franklin_crypto::babyjubjub::{JubjubBn256, JubjubEngine};
    use franklin_crypto::bellman::groth16::{prepare_verifying_key, verify_proof};
    use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
    use verkle_tree::batch_proof_fs::BatchProof;
    use verkle_tree::bn256_verkle_tree_fs::proof::VerkleProof;
    use verkle_tree::bn256_verkle_tree_fs::VerkleTreeWith32BytesKeyValue;
    use verkle_tree::ipa_fs::config::IpaConfig;
    use verkle_tree::ipa_fs::transcript::{Bn256Transcript, PoseidonBn256Transcript};
    use verkle_tree::verkle_tree::witness::Elements;

    use crate::api::batch_proof_fs::input::BatchProofCircuitInput;

    const CIRCUIT_NAME: &str = "verkle_tree";

    fn make_test_input(
        tree: &mut VerkleTreeWith32BytesKeyValue,
        keys: &[[u8; 32]],
        transcript_params: Fr,
        jubjub_params: &<Bn256 as JubjubEngine>::Params,
        ipa_conf: &IpaConfig<Bn256>,
    ) -> anyhow::Result<BatchProofCircuitInput> {
        tree.compute_digest().unwrap();

        let result = tree.get_witnesses(keys).unwrap();
        // println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("zs: {:?}", result.commitment_elements.elements.zs);
        println!("ys: {:?}", result.commitment_elements.elements.ys);

        let (proof, elements) = VerkleProof::create(tree, keys).unwrap();

        let commitments = proof.commitments;
        let Elements { fs, zs, ys } = elements;
        let (proof, _) = BatchProof::<Bn256>::create(
            &commitments,
            &fs,
            &zs,
            transcript_params,
            ipa_conf,
            jubjub_params,
        )?;

        Ok(BatchProofCircuitInput {
            proof: proof.clone(),
            commitments,
            zs,
            ys,
        })
    }

    #[test]
    fn test_verkle_proof_circuit_case1() -> Result<(), Box<dyn std::error::Error>> {
        let domain_size = 4;
        let jubjub_params = &JubjubBn256::new();
        let ipa_conf = &IpaConfig::new(domain_size, jubjub_params);

        // Prover view
        let committer = IpaConfig::new(domain_size, jubjub_params);
        let mut tree = VerkleTreeWith32BytesKeyValue::new(committer);
        let mut key = [0u8; 32];
        key[0] = 1;
        let mut value = [0u8; 32];
        value[0] = 27;
        tree.insert(key, value);
        let mut key = [0u8; 32];
        key[0] = 1;
        key[1] = 3;
        let mut value = [0u8; 32];
        value[0] = 85;
        tree.insert(key, value);
        let keys = [key];
        let prover_transcript = PoseidonBn256Transcript::with_bytes(b"verkle_tree");

        // let output = read_field_element_le_from::<Fr>(&[
        //   251, 230, 185, 64, 12, 136, 124, 164, 37, 71, 120, 65, 234, 225, 30, 7, 157, 148, 169, 225,
        //   186, 183, 76, 63, 231, 241, 40, 189, 50, 55, 145, 23,
        // ])
        // .unwrap();
        let circuit_input = make_test_input(
            &mut tree,
            &keys,
            prover_transcript.clone().into_params(),
            jubjub_params,
            ipa_conf,
        )?;

        let (vk, proof) = circuit_input
            .create_groth16_proof(prover_transcript.into_params(), ipa_conf, jubjub_params)
            .unwrap();
        let public_input = vec![]; // TODO
        let prepared_vk = prepare_verifying_key(&vk);
        let success = verify_proof(&prepared_vk, &proof, &public_input)?;
        assert!(success, "verification error");

        let proof_path = Path::new("./test_cases")
            .join(CIRCUIT_NAME)
            .join("proof_case1");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(proof_path)?;
        proof.write(file)?;
        let vk_proof = Path::new("./test_cases")
            .join(CIRCUIT_NAME)
            .join("vk_case1");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(vk_proof)?;
        vk.write(file)?;

        Ok(())
    }
}
