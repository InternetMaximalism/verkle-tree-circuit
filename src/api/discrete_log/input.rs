use franklin_crypto::{
    babyjubjub::{edwards, JubjubBn256, JubjubEngine, Unknown},
    bellman::{
        kate_commitment::{Crs, CrsForMonomialForm},
        pairing::bn256::Bn256,
        plonk::{
            better_better_cs::{
                cs::{
                    Circuit, ProvingAssembly, SetupAssembly, TrivialAssembly,
                    Width4MainGateWithDNext,
                },
                proof::Proof,
                setup::VerificationKey,
            },
            commitments::transcript::keccak_transcript::RollingKeccakTranscript,
        },
        ScalarEngine, SynthesisError,
    },
    plonk::circuit::{
        bigint::field::RnsParameters,
        verifier_circuit::affine_point_wrapper::aux_data::{AuxData, BN256AuxData},
        Width4WithCustomGates,
    },
};

use crate::circuit::discrete_log::DiscreteLogCircuit;
// use serde::{Deserialize, Serialize};

// use crate::circuit::utils::read_field_element_le_from;

pub struct DiscreteLogCircuitInput {
    pub base_point: edwards::Point<Bn256, Unknown>,
    pub coefficient: <Bn256 as JubjubEngine>::Fs,
}

#[test]
fn test_discrete_log_circuit() -> Result<(), Box<dyn std::error::Error>> {
    use franklin_crypto::babyjubjub::fs::{Fs, FsRepr};
    use franklin_crypto::babyjubjub::{edwards, JubjubBn256, JubjubEngine, Unknown};
    use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr, FrRepr};
    use franklin_crypto::bellman::plonk::better_better_cs::verifier::verify;
    use franklin_crypto::bellman::{PrimeField, PrimeFieldRepr};
    use franklin_crypto::plonk::circuit::bigint::field::RnsParameters;
    use std::{fs::OpenOptions, path::Path};

    use crate::api::discrete_log::input::DiscreteLogCircuitInput;
    use crate::api::utils::open_crs_for_log2_of_size;

    const CIRCUIT_NAME: &str = "discrete_log";

    let mut rns_params =
        RnsParameters::<Bn256, <Bn256 as JubjubEngine>::Fs>::new_for_field(68, 110, 4);
    // `Bn256::Fs::NUM_BITS` is odd number, so an assertion error occur at franklin-crypto/plonk/circuit/bigint/field.rs:400:9.
    // Therefore, we modify `rns_params.binary_limbs_bit_widths[3]` to the next even number.
    dbg!(rns_params.binary_limbs_bit_widths.last().unwrap());
    let current_bits = rns_params.binary_limbs_bit_widths.last_mut().unwrap();
    let remainder = *current_bits % rns_params.range_check_info.minimal_multiple;
    if remainder != 0 {
        *current_bits += rns_params.range_check_info.minimal_multiple - remainder;
    }
    dbg!(rns_params.binary_limbs_bit_widths.last().unwrap());

    let jubjub_params = &JubjubBn256::new();

    // NOTE: Run `cargo run crs create` command in advance.
    let crs = open_crs_for_log2_of_size(14);

    // base_point * coefficient = output
    let base_point_x = Fr::from_repr(FrRepr([
        0x6c1e3b06bd84f358,
        0x5ea091f77966fbcf,
        0x561a4a558403ae2b,
        0x1a3d11d431cd306a,
    ]))?;
    let base_point_y = Fr::from_repr(FrRepr([
        0x1f334e763bfd6753,
        0xeb3d004136b45cfc,
        0x9fbacc86a287b5b1,
        0x190eddeda5ed1c18,
    ]))?;
    let coefficient = Fs::from_repr(FsRepr([10493827077, 0, 0, 0]))?;
    let output_x = Fr::from_repr(FrRepr([
        0x59b7209c8083e1c5,
        0xb6e58c81e6e5cbf3,
        0x171d65a48a5118dc,
        0x2ff3d07fa6e63313,
    ]))?;
    let output_y = Fr::from_repr(FrRepr([
        0xf2d04f4c1966e838,
        0xf6d49deddbb01b22,
        0xd3548e1718b2de12,
        0x1c9e54dffc5181d8,
    ]))?;
    let base_point = edwards::Point::<Bn256, Unknown>::get_for_y(
        base_point_y,
        base_point_x.into_repr().is_odd(),
        jubjub_params,
    )
    .unwrap();
    let output = base_point.mul(coefficient, jubjub_params);
    assert_eq!(output.into_xy(), (output_x, output_y));

    // Create a PlonK proof and a verification key.
    let circuit_input = DiscreteLogCircuitInput {
        base_point,
        coefficient,
    };
    let (vk, proof) = circuit_input.create_plonk_proof(jubjub_params, &rns_params, crs)?;

    // Verify the proof.
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

impl DiscreteLogCircuitInput {
    pub fn new(
        base_point: edwards::Point<Bn256, Unknown>,
        coefficient: <Bn256 as JubjubEngine>::Fs,
    ) -> Self {
        Self {
            base_point,
            coefficient,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn create_plonk_proof(
        &self,
        jubjub_params: &JubjubBn256,
        rns_params: &RnsParameters<Bn256, <Bn256 as JubjubEngine>::Fs>,
        crs: Crs<Bn256, CrsForMonomialForm>,
    ) -> Result<
        (
            VerificationKey<Bn256, DiscreteLogCircuit<Bn256, BN256AuxData>>,
            Proof<Bn256, DiscreteLogCircuit<Bn256, BN256AuxData>>,
        ),
        SynthesisError,
    > {
        let aux_data = BN256AuxData::new();
        let dummy_circuit = DiscreteLogCircuit::<Bn256, BN256AuxData> {
            base_point: None,
            coefficient: None,
            output: None,
            rns_params,
            aux_data: aux_data.clone(),
            jubjub_params,
        };

        let output = self.base_point.mul(self.coefficient, jubjub_params);
        let circuit = DiscreteLogCircuit::<Bn256, BN256AuxData> {
            base_point: Some(self.base_point.clone()),
            coefficient: Some(self.coefficient),
            output: Some(output),
            rns_params,
            aux_data,
            jubjub_params,
        };

        let mut dummy_assembly =
            SetupAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
        dummy_circuit
            .synthesize(&mut dummy_assembly)
            .expect("must synthesize");
        dummy_assembly.finalize();

        let worker = franklin_crypto::bellman::worker::Worker::new();
        let setup =
            dummy_assembly.create_setup::<DiscreteLogCircuit<Bn256, BN256AuxData>>(&worker)?;

        let vk = VerificationKey::<Bn256, DiscreteLogCircuit<Bn256, BN256AuxData>>::from_setup(
            &setup, &worker, &crs,
        )?;

        println!("Checking if satisfied");
        let mut trivial_assembly =
            TrivialAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
        circuit
            .synthesize(&mut trivial_assembly)
            .expect("must synthesize");
        if !trivial_assembly.is_satisfied() {
            return Err(SynthesisError::Unsatisfiable);
        }

        println!("prove");

        let mut assembly =
            ProvingAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
        circuit.synthesize(&mut assembly).expect("must synthesize");
        assembly.finalize();

        // TODO: Is this correct?
        let proof = assembly
    .create_proof::<DiscreteLogCircuit<Bn256, BN256AuxData>, RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>>(
      &worker, &setup, &crs, None,
    )?;

        dbg!(&proof.inputs);

        let result = (vk, proof);

        Ok(result)
    }
}

// impl FromStr for DisCreteLogCircuitInput {
//     type Err = anyhow::Error;

//     fn from_str(s: &str) -> anyhow::Result<Self> {
//         Self::from_bytes(s.as_bytes())
//     }
// }

// impl DisCreteLogCircuitInput {
//     pub fn from_path(path: &Path) -> anyhow::Result<Self> {
//         let json_str = read_to_string(path)?;

//         Self::from_str(&json_str)
//     }

//     pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
//         assert_eq!(bytes.to_vec().len(), 96);
//         let reader = &mut std::io::Cursor::new(bytes.to_vec());
//         let base_point_x = read_field_element_le_from(reader).unwrap();
//         let base_point_y = read_field_element_le_from(reader).unwrap();
//         let coefficient = read_field_element_le_from(reader).unwrap();
//         let input = Self {
//             base_point_x: Some(base_point_x),
//             base_point_y: Some(base_point_y),
//             coefficient: Some(coefficient),
//         };

//         Ok(input)
//     }

//     pub fn default() -> Self {
//         Self {
//             base_point_x: None,
//             base_point_y: None,
//             coefficient: None,
//         }
//     }
// }
