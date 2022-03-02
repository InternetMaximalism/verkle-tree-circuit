use std::str::FromStr;
use std::{fs::read_to_string, path::Path};

use franklin_crypto::bellman::plonk::better_better_cs::cs::{
    Circuit, ProvingAssembly, SetupAssembly, Width4MainGateWithDNext,
};
use franklin_crypto::bellman::plonk::better_better_cs::proof::Proof;
use franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;
use franklin_crypto::bellman::{ScalarEngine, SynthesisError};
use franklin_crypto::plonk::circuit::Width4WithCustomGates;
use franklin_crypto::{
    bellman::kate_commitment::{Crs, CrsForMonomialForm},
    plonk::circuit::verifier_circuit::affine_point_wrapper::{
        aux_data::AuxData, WrappedAffinePoint,
    },
};
use franklin_crypto::{
    bellman::pairing::bn256::{Bn256, Fr, G1Affine},
    plonk::circuit::verifier_circuit::affine_point_wrapper::aux_data::BN256AuxData,
};
use verkle_tree::ipa_fr::config::IpaConfig;
use verkle_tree::ipa_fr::proof::IpaProof;
use verkle_tree::ipa_fr::rns::BaseRnsParameters;

use crate::circuit::batch_proof_fr::BatchProofCircuit;
use crate::circuit::ipa_fr::proof::OptionIpaProof;

pub struct BatchProofCircuitInput {
    pub proof: IpaProof<G1Affine>,
    pub d: G1Affine,
    pub commitments: Vec<G1Affine>,
    pub ys: Vec<Fr>,
    pub zs: Vec<u8>,
}

#[cfg(test)]
mod batch_proof_api_tests {
    use std::fs::{File, OpenOptions};
    use std::path::Path;

    use franklin_crypto::bellman::kate_commitment::{Crs, CrsForMonomialForm};
    use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr, G1Affine};
    use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::without_flag_unchecked::WrapperUnchecked;
    use verkle_tree::batch_proof_fr::BatchProof;
    use verkle_tree::ipa_fr::config::{IpaConfig, Committer};
    use verkle_tree::ipa_fr::rns::BaseRnsParameters;
    use verkle_tree::ipa_fr::transcript::{PoseidonBn256Transcript, Bn256Transcript};
    use verkle_tree::ipa_fr::utils::test_poly;

    use super::{BatchProofCircuitInput, VkAndProof};

    const CIRCUIT_NAME: &str = "batch_proof_fr";

    fn make_test_input(
        fs: Vec<Vec<Fr>>,
        zs: Vec<usize>,
        transcript_params: Fr,
        rns_params: &BaseRnsParameters<Bn256>,
        ipa_conf: &IpaConfig<G1Affine>,
    ) -> anyhow::Result<BatchProofCircuitInput> {
        let commitments = fs
            .iter()
            .map(|fi| ipa_conf.commit(fi))
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap();
        let proof = BatchProof::<G1Affine>::create(
            &commitments,
            &fs,
            &zs,
            transcript_params,
            rns_params,
            &ipa_conf,
        )?;

        let ys = fs
            .iter()
            .zip(&zs)
            .map(|(fi, &zi)| fi[zi])
            .collect::<Vec<_>>();

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
    fn test_batch_proof_circuit_case1() -> Result<(), Box<dyn std::error::Error>> {
        let crs = open_crs_for_log2_of_size(23);
        let domain_size = 2;
        let ipa_conf = IpaConfig::<G1Affine>::new(domain_size);
        let rns_params = &BaseRnsParameters::<Bn256>::new_for_field(68, 110, 4);

        // Prover view
        let polys = vec![vec![12, 97], vec![37, 0]];
        // let poly = vec![12, 97, 37, 0, 1, 208, 132, 3];
        let fs = polys
            .iter()
            .map(|poly| test_poly::<Fr>(&poly, domain_size))
            .collect::<Vec<_>>();
        let zs = vec![1, 0];
        let prover_transcript = PoseidonBn256Transcript::with_bytes(b"ipa");

        // let output = read_field_element_le_from::<Fr>(&[
        //   251, 230, 185, 64, 12, 136, 124, 164, 37, 71, 120, 65, 234, 225, 30, 7, 157, 148, 169, 225,
        //   186, 183, 76, 63, 231, 241, 40, 189, 50, 55, 145, 23,
        // ])
        // .unwrap();
        let circuit_input = make_test_input(
            fs,
            zs,
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

pub struct VkAndProof<'a, WP: WrappedAffinePoint<'a, Bn256>, AD: AuxData<Bn256>>(
    pub VerificationKey<Bn256, BatchProofCircuit<'a, Bn256, WP, AD>>,
    pub Proof<Bn256, BatchProofCircuit<'a, Bn256, WP, AD>>,
);

impl BatchProofCircuitInput {
    pub fn create_plonk_proof<'a, WP: WrappedAffinePoint<'a, Bn256>>(
        &self,
        transcript_params: Fr,
        ipa_conf: IpaConfig<G1Affine>,
        rns_params: &'a BaseRnsParameters<Bn256>,
        crs: Crs<Bn256, CrsForMonomialForm>,
    ) -> Result<VkAndProof<'a, WP, BN256AuxData>, SynthesisError> {
        // let dummy_circuit = PoseidonCircuit::<Bn256> {
        //   inputs: inputs.iter().map(|&_| None).collect::<Vec<_>>(),
        //   output: None,
        // };

        let aux_data = BN256AuxData::new();
        let wrapped_proof = OptionIpaProof::from(self.proof.clone());
        let circuit = BatchProofCircuit::<'a, Bn256, WP, BN256AuxData> {
            transcript_params: Some(transcript_params),
            proof: wrapped_proof,
            d: Some(self.d),
            commitments: self
                .commitments
                .iter()
                .map(|&ci| Some(ci))
                .collect::<Vec<_>>(),
            ys: self.ys.iter().map(|&yi| Some(yi)).collect::<Vec<_>>(),
            zs: self.zs.iter().map(|&zi| Some(zi)).collect::<Vec<_>>(),
            ipa_conf,
            rns_params,
            aux_data,
            _wp: std::marker::PhantomData,
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
        let setup = dummy_assembly
            .create_setup::<BatchProofCircuit<'a, Bn256, WP, BN256AuxData>>(&worker)?;

        let vk =
            VerificationKey::<Bn256, BatchProofCircuit<'a, Bn256, WP, BN256AuxData>>::from_setup(
                &setup, &worker, &crs,
            )?;

        let mut assembly =
            ProvingAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
        circuit.synthesize(&mut assembly).expect("must synthesize");
        assembly.finalize();

        println!("prove");

        let proof = assembly
            .create_proof::<BatchProofCircuit<'a, Bn256, WP, BN256AuxData>, RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>>(
                &worker, &setup, &crs, None,
            )?;

        // assert_eq!(
        //     proof.inputs,
        //     vec![self.output],
        //     "expected input is not equal to one in a circuit"
        // );

        let result = VkAndProof(vk, proof);

        Ok(result)
    }

    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let json_str = read_to_string(path)?;

        Self::from_str(&json_str)
    }

    pub fn from_bytes(_bytes: &[u8]) -> anyhow::Result<Self> {
        todo!()
    }
}

impl FromStr for BatchProofCircuitInput {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        Self::from_bytes(s.as_bytes())
    }
}
