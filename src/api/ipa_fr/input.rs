use std::{
    fs::read_to_string,
    io::{Read, Write},
    path::Path,
    str::FromStr,
};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use franklin_crypto::bellman::plonk::better_better_cs::proof::Proof;
use franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;
use franklin_crypto::bellman::{
    plonk::better_better_cs::cs::{
        Circuit, ProvingAssembly, SetupAssembly, Width4MainGateWithDNext,
    },
    CurveAffine,
};
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
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use verkle_tree::ipa_fr::{
    config::{Committer, IpaConfig},
    proof::{IpaProof, SerializableIpaProof},
    rns::BaseRnsParameters,
    utils::log2_ceil,
};

use crate::circuit::ipa_fr::circuit::IpaCircuit;
use crate::circuit::ipa_fr::proof::OptionIpaProof;
use crate::circuit::utils::{read_field_element_le_from, write_field_element_le_into};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpaCircuitInput {
    pub commitment: G1Affine,
    pub proof: IpaProof<G1Affine>,
    pub eval_point: Fr,
    pub inner_prod: Fr,
}

#[cfg(test)]
mod ipa_api_tests {
    use std::fs::{read_to_string, File, OpenOptions};
    use std::io::Write;
    use std::path::Path;

    use franklin_crypto::bellman::kate_commitment::{Crs, CrsForMonomialForm};
    use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr, G1Affine};
    use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::without_flag_unchecked::WrapperUnchecked;
    use verkle_tree::ipa_fr::config::{IpaConfig, Committer};
    use verkle_tree::ipa_fr::proof::IpaProof;
    use verkle_tree::ipa_fr::rns::BaseRnsParameters;
    use verkle_tree::ipa_fr::transcript::{PoseidonBn256Transcript, Bn256Transcript};
    use verkle_tree::ipa_fr::utils::{read_field_element_le, test_poly};

    use super::{IpaCircuitInput, VkAndProof};

    const CIRCUIT_NAME: &str = "ipa_fr";

    fn make_test_input(
        poly: &[Fr],
        eval_point: Fr,
        transcript_params: Fr,
        rns_params: &BaseRnsParameters<Bn256>,
        ipa_conf: &IpaConfig<G1Affine>,
    ) -> anyhow::Result<IpaCircuitInput> {
        let commitment = ipa_conf.commit(&poly).unwrap();
        let (proof, ip) = IpaProof::<G1Affine>::create(
            commitment,
            poly,
            eval_point,
            transcript_params,
            rns_params,
            &ipa_conf,
        )?;

        // let lagrange_coeffs = ipa_conf
        //     .precomputed_weights
        //     .compute_barycentric_coefficients(&eval_point)?;
        // let _ip = inner_prod(&poly, &lagrange_coeffs)?;
        // assert_eq!(_ip, ip);

        Ok(IpaCircuitInput {
            commitment,
            proof,
            eval_point,
            inner_prod: ip,
        })
    }

    fn open_crs_for_log2_of_size(_log2_n: usize) -> Crs<Bn256, CrsForMonomialForm> {
        let full_path = Path::new("./test_cases").join("crs");
        println!("Opening {}", full_path.to_string_lossy());
        let file = File::open(&full_path).unwrap();
        let reader = std::io::BufReader::with_capacity(1 << 24, file);
        let crs = Crs::<Bn256, CrsForMonomialForm>::read(reader).unwrap();
        println!("Load {}", full_path.to_string_lossy());

        crs
    }

    #[test]
    fn test_ipa_fr_circuit_case1() -> Result<(), Box<dyn std::error::Error>> {
        let crs = open_crs_for_log2_of_size(23);
        let eval_point: Fr = read_field_element_le(&123456789u64.to_le_bytes()).unwrap();
        let domain_size = 2;
        let ipa_conf = IpaConfig::<G1Affine>::new(domain_size);

        // Prover view
        let poly = vec![12, 97];
        // let poly = vec![12, 97, 37, 0, 1, 208, 132, 3];
        let padded_poly = test_poly::<Fr>(&poly, domain_size);
        let prover_transcript = PoseidonBn256Transcript::with_bytes(b"ipa");

        // let output = read_field_element_le_from::<Fr>(&[
        //   251, 230, 185, 64, 12, 136, 124, 164, 37, 71, 120, 65, 234, 225, 30, 7, 157, 148, 169, 225,
        //   186, 183, 76, 63, 231, 241, 40, 189, 50, 55, 145, 23,
        // ])
        // .unwrap();
        let rns_params = &BaseRnsParameters::<Bn256>::new_for_field(68, 110, 4);
        let circuit_input = make_test_input(
            &padded_poly,
            eval_point,
            prover_transcript.into_params(),
            rns_params,
            &ipa_conf,
        )?;

        let VkAndProof(vk, proof) = circuit_input
            .create_plonk_proof::<WrapperUnchecked<'_, Bn256>>(
                prover_transcript.into_params(),
                ipa_conf,
                &rns_params,
                crs,
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

        Ok(())
    }

    #[test]
    fn test_ipa_fr_circuit_input_read_write() -> Result<(), Box<dyn std::error::Error>> {
        let eval_point: Fr = read_field_element_le(&123456789u64.to_le_bytes()).unwrap();
        let domain_size = 8;
        let ipa_conf = IpaConfig::<G1Affine>::new(domain_size);
        let rns_params = &BaseRnsParameters::<Bn256>::new_for_field(68, 110, 4);

        // Prover view
        let poly = vec![12, 97, 37, 0, 1, 208, 132, 3];
        let padded_poly = test_poly::<Fr>(&poly, domain_size);
        let commitment = ipa_conf.commit(&padded_poly).unwrap();
        let prover_transcript = PoseidonBn256Transcript::with_bytes(b"ipa");

        let (proof, ip) = IpaProof::<G1Affine>::create(
            commitment,
            &padded_poly,
            eval_point,
            prover_transcript.into_params(),
            rns_params,
            &ipa_conf,
        )?;

        // let lagrange_coeffs = ipa_conf
        //     .precomputed_weights
        //     .compute_barycentric_coefficients(&eval_point)?;
        // let _ip = inner_prod(&padded_poly, &lagrange_coeffs)?;
        // assert_eq!(_ip, ip);

        let circuit_input = IpaCircuitInput {
            commitment,
            proof,
            eval_point,
            inner_prod: ip,
        };

        let file_path = Path::new("./test_cases")
            .join(CIRCUIT_NAME)
            .join("public_inputs");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_path)?;
        circuit_input.write_into(&mut file)?;
        println!("write circuit_input into {:?}", file_path);

        let mut file = OpenOptions::new().read(true).open(&file_path)?;
        let circuit_input2 = IpaCircuitInput::read_from(&mut file)?;
        println!("read circuit_input2 from {:?}", file_path);

        assert_eq!(
            circuit_input, circuit_input2,
            "expect circuit input: {:?}, but {:?}",
            circuit_input, circuit_input2
        );

        Ok(())
    }

    #[test]
    fn test_ipa_fr_circuit_input_serde_json() -> Result<(), Box<dyn std::error::Error>> {
        let eval_point: Fr = read_field_element_le(&123456789u64.to_le_bytes()).unwrap();
        let domain_size = 8;
        let ipa_conf = IpaConfig::<G1Affine>::new(domain_size);
        let rns_params = &BaseRnsParameters::<Bn256>::new_for_field(68, 110, 4);

        // Prover view
        let poly = vec![12, 97, 37, 0, 1, 208, 132, 3];
        let padded_poly = test_poly::<Fr>(&poly, domain_size);
        let commitment = ipa_conf.commit(&padded_poly).unwrap();
        let prover_transcript = PoseidonBn256Transcript::with_bytes(b"ipa");

        let (proof, ip) = IpaProof::<G1Affine>::create(
            commitment,
            &padded_poly,
            eval_point,
            prover_transcript.into_params(),
            rns_params,
            &ipa_conf,
        )?;

        // let lagrange_coeffs = ipa_conf
        //     .precomputed_weights
        //     .compute_barycentric_coefficients(&eval_point)?;
        // let _ip = inner_prod(&padded_poly, &lagrange_coeffs)?;
        // assert_eq!(_ip, ip);

        let file_path = Path::new("./test_cases")
            .join(CIRCUIT_NAME)
            .join("public_inputs.json");
        let path = std::env::current_dir()?;
        let path = path.join(&file_path);

        let circuit_input = IpaCircuitInput {
            commitment,
            proof,
            eval_point,
            inner_prod: ip,
        };

        let j = serde_json::to_string(&circuit_input)?;
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)?;
        write!(file, "{}", j)?;
        println!("write circuit_input into {:?}", file_path);

        let raw = read_to_string(path)?;
        let circuit_input2: IpaCircuitInput = serde_json::from_str(&raw)?;
        println!("read circuit_input2 from {:?}", file_path);

        assert_eq!(circuit_input, circuit_input2);

        Ok(())
    }
}

pub struct VkAndProof<'a, WP: WrappedAffinePoint<'a, Bn256>, AD: AuxData<Bn256>>(
    pub VerificationKey<Bn256, IpaCircuit<'a, Bn256, WP, AD>>,
    pub Proof<Bn256, IpaCircuit<'a, Bn256, WP, AD>>,
);

impl IpaCircuitInput {
    pub fn new(
        commitment: G1Affine,
        proof: IpaProof<G1Affine>,
        eval_point: Fr,
        inner_prod: Fr,
    ) -> Self {
        Self {
            commitment,
            proof,
            eval_point,
            inner_prod,
        }
    }

    pub fn create_plonk_proof<'a, WP: WrappedAffinePoint<'a, Bn256>>(
        &self,
        transcript_params: Fr,
        ipa_conf: IpaConfig<G1Affine>,
        rns_params: &'a BaseRnsParameters<Bn256>,
        crs: Crs<Bn256, CrsForMonomialForm>,
    ) -> Result<VkAndProof<'a, WP, BN256AuxData>, SynthesisError> {
        let aux_data = BN256AuxData::new();
        let num_rounds = log2_ceil(ipa_conf.get_domain_size()) as usize;
        let dummy_circuit = IpaCircuit::<'a, Bn256, WP, BN256AuxData> {
            transcript_params: None,
            commitment: None,
            proof: OptionIpaProof::with_depth(num_rounds),
            eval_point: None,
            inner_prod: None,
            ipa_conf: ipa_conf.clone(),
            rns_params,
            aux_data: aux_data.clone(),
            _wp: std::marker::PhantomData,
        };

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
        let setup =
            dummy_assembly.create_setup::<IpaCircuit<'a, Bn256, WP, BN256AuxData>>(&worker)?;

        let vk = VerificationKey::<Bn256, IpaCircuit<'a, Bn256, WP, BN256AuxData>>::from_setup(
            &setup, &worker, &crs,
        )?;

        let circuit = IpaCircuit::<'a, Bn256, WP, BN256AuxData> {
            transcript_params: Some(transcript_params),
            commitment: Some(self.commitment),
            proof: OptionIpaProof::from(self.proof.clone()),
            eval_point: Some(self.eval_point),
            inner_prod: Some(self.inner_prod),
            ipa_conf,
            rns_params,
            aux_data,
            _wp: std::marker::PhantomData,
        };

        let mut assembly =
            ProvingAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
        circuit.synthesize(&mut assembly).expect("must synthesize");
        assembly.finalize();

        println!("prove");

        let proof = assembly
            .create_proof::<IpaCircuit<'a, Bn256, WP, BN256AuxData>, RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>>(
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

    /// `[width, input[0], ..., inputs[t - 2], output]` -> `CircuitInput`
    pub fn read_from<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let commitment_x = read_field_element_le_from(reader)?;
        let commitment_y = read_field_element_le_from(reader)?;
        let commitment = G1Affine::from_xy_checked(commitment_x, commitment_y)?;
        let num_ipa_rounds = reader.read_u16::<LittleEndian>()?;

        let mut proof_ls = vec![];
        for _ in 0..num_ipa_rounds {
            let l_x = read_field_element_le_from(reader)?;
            let l_y = read_field_element_le_from(reader)?;
            let l = G1Affine::from_xy_checked(l_x, l_y)?;
            proof_ls.push(l);
        }
        let mut proof_rs = vec![];
        for _ in 0..num_ipa_rounds {
            let r_x = read_field_element_le_from(reader)?;
            let r_y = read_field_element_le_from(reader)?;
            let r = G1Affine::from_xy_checked(r_x, r_y)?;
            proof_rs.push(r);
        }
        let proof_a = read_field_element_le_from(reader)?;
        let proof = IpaProof {
            l: proof_ls,
            r: proof_rs,
            a: proof_a,
        };
        let eval_point = read_field_element_le_from(reader)?;
        let inner_prod = read_field_element_le_from(reader)?;

        let result = Self {
            commitment,
            proof,
            eval_point,
            inner_prod,
        };

        Ok(result)
    }

    /// `CircuitInput` -> `[t, input[0], ..., inputs[t - 2], output]`
    pub fn write_into<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let (commitment_x, commitment_y) = self.commitment.into_xy_unchecked();
        write_field_element_le_into(commitment_x, writer)?;
        write_field_element_le_into(commitment_y, writer)?;
        let num_ipa_rounds = self.proof.l.len();
        assert!(num_ipa_rounds <= u16::MAX as usize);
        writer.write_u16::<LittleEndian>(num_ipa_rounds as u16)?;
        for l in self.proof.l.iter() {
            let (l_x, l_y) = l.into_xy_unchecked();
            write_field_element_le_into(l_x, writer)?;
            write_field_element_le_into(l_y, writer)?;
        }
        for r in self.proof.r.iter() {
            let (r_x, r_y) = r.into_xy_unchecked();
            write_field_element_le_into(r_x, writer)?;
            write_field_element_le_into(r_y, writer)?;
        }
        write_field_element_le_into(self.proof.a, writer)?;
        write_field_element_le_into(self.eval_point, writer)?;
        write_field_element_le_into(self.inner_prod, writer)?;

        Ok(())
    }

    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let json_str = read_to_string(path)?;

        Self::from_str(&json_str)
    }
}

impl FromStr for IpaCircuitInput {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        Self::read_from(&mut s.as_bytes())
    }
}

impl Default for IpaCircuitInput {
    fn default() -> Self {
        todo!()
    }
}

/// `SerializablePoseidonCircuitInput` is needed in the process of serializing `PoseidonCircuitInput`.
/// `PoseidonCircuitInput` is serialized by treating `Fr` as a hex string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SerializableIpaCircuitInput {
    pub(crate) commitment: (String, String),
    pub(crate) proof: SerializableIpaProof,
    pub(crate) eval_point: String,
    pub(crate) inner_prod: String,
}

impl Serialize for IpaCircuitInput {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        todo!()
    }
}

impl<'de> Deserialize<'de> for IpaCircuitInput {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        todo!()
    }
}
