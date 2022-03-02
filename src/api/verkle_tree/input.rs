#[cfg(test)]
mod batch_proof_api_tests {
    use std::fs::{File, OpenOptions};
    use std::path::Path;

    use franklin_crypto::bellman::kate_commitment::{Crs, CrsForMonomialForm};
    use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr, G1Affine};
    use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::without_flag_unchecked::WrapperUnchecked;
    use verkle_tree::batch_proof_fr::BatchProof;
    use verkle_tree::bn256_verkle_tree::VerkleTreeWith32BytesKeyValue;
    use verkle_tree::bn256_verkle_tree::proof::VerkleProof;
    use verkle_tree::ipa_fr::config::{IpaConfig};
    use verkle_tree::ipa_fr::rns::BaseRnsParameters;
    use verkle_tree::ipa_fr::transcript::{PoseidonBn256Transcript, Bn256Transcript};
    use verkle_tree::verkle_tree::witness::Elements;

    use crate::api::batch_proof_fr::input::{BatchProofCircuitInput, VkAndProof};

    const CIRCUIT_NAME: &str = "verkle_tree";

    fn make_test_input(
        tree: &mut VerkleTreeWith32BytesKeyValue,
        keys: &[[u8; 32]],
        transcript_params: Fr,
        rns_params: &BaseRnsParameters<Bn256>,
        ipa_conf: &IpaConfig<G1Affine>,
    ) -> anyhow::Result<BatchProofCircuitInput> {
        tree.compute_commitment().unwrap();

        let result = tree.get_witnesses(keys).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("zs: {:?}", result.commitment_elements.elements.zs);
        println!("ys: {:?}", result.commitment_elements.elements.ys);

        let (proof, elements) = VerkleProof::create(tree, keys).unwrap();

        let commitments = proof.commitments;
        let Elements { fs, zs, ys } = elements;
        let proof = BatchProof::<G1Affine>::create(
            &commitments,
            &fs,
            &zs,
            transcript_params,
            rns_params,
            &ipa_conf,
        )?;

        Ok(BatchProofCircuitInput {
            proof: proof.ipa,
            commitments,
            d: proof.d,
            zs: zs.iter().map(|&zi| zi as u8).collect::<Vec<_>>(),
            ys,
        })
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
    fn test_verkle_proof_circuit_case1() -> Result<(), Box<dyn std::error::Error>> {
        let crs = open_crs_for_log2_of_size(23);
        let domain_size = 4;
        let ipa_conf = IpaConfig::<G1Affine>::new(domain_size);
        let rns_params = &BaseRnsParameters::<Bn256>::new_for_field(68, 110, 4);

        // Prover view
        let committer = IpaConfig::new(domain_size);
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
            prover_transcript.into_params(),
            rns_params,
            &ipa_conf,
        )?;

        let VkAndProof(vk, proof) = circuit_input
            .create_plonk_proof::<WrapperUnchecked<'_, Bn256>>(
                prover_transcript.into_params(),
                ipa_conf,
                rns_params,
                crs,
            )?;
        let proof_path = Path::new("./tests").join(CIRCUIT_NAME).join("proof_case1");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(proof_path)?;
        proof.write(file)?;
        let vk_proof = Path::new("./tests").join(CIRCUIT_NAME).join("vk_case1");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(vk_proof)?;
        vk.write(file)?;

        Ok(())
    }
}
