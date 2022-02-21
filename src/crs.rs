#[cfg(test)]
mod crs_tests {
    use std::fs::File;

    use franklin_crypto::bellman::kate_commitment::{Crs, CrsForMonomialForm};
    use franklin_crypto::bellman::pairing::bn256::Bn256;

    fn create_crs_for_log2_of_size(log2_n: usize) -> Crs<Bn256, CrsForMonomialForm> {
        let worker = franklin_crypto::bellman::worker::Worker::new();

        Crs::<Bn256, CrsForMonomialForm>::crs_42(1 << log2_n, &worker)
    }

    #[test]
    fn test_crs_serialization() {
        let path = std::env::current_dir().unwrap();
        let path = path.join("tests/crs");
        let mut file = File::create(path).unwrap();
        let crs = create_crs_for_log2_of_size(21); // < 2097152 constraints (?)
        crs.write(&mut file).expect("must serialize CRS");
    }
}

use std::{fs::File, path::Path};

use franklin_crypto::bellman::pairing::bn256::Bn256;

/// A subcommand for generating a SNARK proof
struct ProveOpts {
    /// Source file for Plonk universal setup srs in monomial form
    srs_monomial_form: String,
    /// Source file for Plonk universal setup srs in lagrange form
    srs_lagrange_form: Option<String>,
    /// Circuit R1CS or JSON file [default: circuit.r1cs|circuit.json]
    circuit: Option<String>,
    /// Witness BIN or JSON file
    witness: String,
    /// Output file for proof BIN
    proof: String,
    /// Output file for proof json
    proof_json: String,
    /// Output file for public input json
    public_json: String,
    transcript: String,
    overwrite: bool,
}

/// A subcommand for verifying a SNARK proof
struct VerifyOpts {
    /// Proof BIN file
    proof: String,
    /// Verification key file
    vk: String,
    transcript: String,
}

// generate a plonk proof for a circuit, with witness loaded, and save the proof to a file
pub fn prove(opts: ProveOpts) {
    let circuit_file = resolve_circuit_file(opts.circuit);
    println!("Loading circuit from {}...", circuit_file);
    let circuit = CircomCircuit {
        r1cs: plonkit::reader::load_r1cs(&circuit_file),
        witness: Some(plonkit::reader::load_witness_from_file::<Bn256>(
            &opts.witness,
        )),
        wire_mapping: None,
        aux_offset: plonkit::plonk::AUX_OFFSET,
    };

    let setup = plonkit::plonk::SetupForProver::prepare_setup_for_prover(
        circuit.clone(),
        plonkit::reader::load_key_monomial_form(&opts.srs_monomial_form),
        plonkit::reader::maybe_load_key_lagrange_form(opts.srs_lagrange_form),
    )
    .expect("prepare err");

    println!("Proving...");
    let proof = setup.prove(circuit, &opts.transcript).unwrap();
    if !opts.overwrite {
        let path = Path::new(&opts.proof);
        assert!(!path.exists(), "duplicate proof file: {}", path.display());
    }
    let writer = File::create(&opts.proof).unwrap();
    proof.write(writer).unwrap();
    println!("Proof saved to {}", opts.proof);

    let (inputs, serialized_proof) = plonkit::bellman_vk_codegen::serialize_proof(&proof);
    let ser_proof_str = serde_json::to_string_pretty(&serialized_proof).unwrap();
    let ser_inputs_str = serde_json::to_string_pretty(&inputs).unwrap();
    if !opts.overwrite {
        let path = Path::new(&opts.proof_json);
        assert!(
            !path.exists(),
            "duplicate proof json file: {}",
            path.display()
        );
        let path = Path::new(&opts.public_json);
        assert!(
            !path.exists(),
            "duplicate input json file: {}",
            path.display()
        );
    }
    std::fs::write(&opts.proof_json, ser_proof_str.as_bytes()).expect("save proof_json err");
    println!("Proof json saved to {}", opts.proof_json);
    std::fs::write(&opts.public_json, ser_inputs_str.as_bytes()).expect("save public_json err");
    println!("Public input json saved to {}", opts.public_json);
}

// verify a plonk proof by using a verification key
pub fn verify(opts: VerifyOpts) {
    let vk = plonkit::reader::load_verification_key::<Bn256>(&opts.vk);

    let proof = plonkit::reader::load_proof::<Bn256>(&opts.proof);
    let correct =
        plonkit::plonk::verify(&vk, &proof, &opts.transcript).expect("fail to verify proof");
    if correct {
        println!("Proof is valid.");
    } else {
        println!("Proof is invalid!");
        std::process::exit(400);
    }
}
