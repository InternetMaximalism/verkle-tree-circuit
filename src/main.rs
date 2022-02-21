use verkle_circuit::command::invoke_command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    exec_ipa_fr_circuit_case1()?;

    Ok(())
}

use std::fs::{read_to_string, File, OpenOptions};
use std::io::Write;
use std::path::Path;

use franklin_crypto::bellman::bn256::G1;
use franklin_crypto::bellman::kate_commitment::{Crs, CrsForMonomialForm};
use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::without_flag_unchecked::WrapperUnchecked;
use verkle_tree::ipa_fr::config::{IpaConfig, Committer};
use verkle_tree::ipa_fr::rns::BaseRnsParameters;
use verkle_tree::ipa_fr::{Bn256Ipa, Ipa};
use verkle_tree::ipa_fr::transcript::{PoseidonBn256Transcript, Bn256Transcript};
use verkle_tree::ipa_fr::utils::{read_field_element_le, test_poly};

use verkle_circuit::api::ipa_fr::input::{IpaCircuitInput, VkAndProof};

const CIRCUIT_NAME: &str = "ipa";

fn exec_ipa_fr_circuit_case1() -> Result<(), Box<dyn std::error::Error>> {
    let crs = open_crs_for_log2_of_size(21);
    let eval_point: Fr = read_field_element_le(&123456789u64.to_le_bytes()).unwrap();
    let domain_size = 2;
    let ipa_conf = IpaConfig::<G1>::new(domain_size);

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
    let circuit_input = make_test_input(
        &padded_poly,
        eval_point,
        prover_transcript.into_params(),
        &ipa_conf,
    )?;

    let rns_params = BaseRnsParameters::<Bn256>::new_for_field(68, 110, 4);
    let VkAndProof(vk, proof) = circuit_input.create_plonk_proof::<WrapperUnchecked<'_, Bn256>>(
        prover_transcript.into_params(),
        ipa_conf,
        &rns_params,
        crs,
    )?;
    let proof_path = Path::new("./tests").join(CIRCUIT_NAME).join("proof_case1");
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(proof_path)?;
    proof.write(file)?;
    let vk_path = Path::new("./tests").join(CIRCUIT_NAME).join("vk_case1");
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(vk_path)?;
    vk.write(file)?;

    Ok(())
}

fn open_crs_for_log2_of_size(_log2_n: usize) -> Crs<Bn256, CrsForMonomialForm> {
    let full_path = Path::new("./tests").join(CIRCUIT_NAME).join("crs");
    println!("Opening {}", full_path.to_string_lossy());
    let file = File::open(&full_path).unwrap();
    let reader = std::io::BufReader::with_capacity(1 << 24, file);
    let crs = Crs::<Bn256, CrsForMonomialForm>::read(reader).unwrap();
    println!("Load {}", full_path.to_string_lossy());

    crs
}

fn make_test_input(
    poly: &[Fr],
    eval_point: Fr,
    transcript_params: Fr,
    ipa_conf: &IpaConfig<G1>,
) -> anyhow::Result<IpaCircuitInput> {
    let commitment = ipa_conf.commit(&poly).unwrap();
    let (proof, ip) =
        Bn256Ipa::create_proof(commitment, poly, eval_point, transcript_params, &ipa_conf)?;

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
