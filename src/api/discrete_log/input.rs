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
    plonk::circuit::{bigint::field::RnsParameters, Width4WithCustomGates},
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
    use franklin_crypto::bellman::{PrimeField, PrimeFieldRepr};
    use franklin_crypto::plonk::circuit::bigint::field::RnsParameters;

    use crate::api::discrete_log::input::DiscreteLogCircuitInput;
    use crate::api::utils::open_crs_for_log2_of_size;

    let mut rns_params =
        RnsParameters::<Bn256, <Bn256 as JubjubEngine>::Fs>::new_for_field(68, 110, 4);
    let current_bits = rns_params.binary_limbs_bit_widths.last_mut().unwrap();
    let remainder = *current_bits % rns_params.range_check_info.minimal_multiple;
    if remainder != 0 {
        *current_bits += rns_params.range_check_info.minimal_multiple - remainder;
    }
    dbg!(rns_params.binary_limbs_bit_widths.last_mut().unwrap());
    let jubjub_params = &JubjubBn256::new();
    let crs = open_crs_for_log2_of_size(23);

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
    let circuit_input = DiscreteLogCircuitInput {
        base_point,
        coefficient,
    };
    circuit_input.create_plonk_proof(jubjub_params, &rns_params, crs)?;

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

    pub fn create_plonk_proof(
        &self,
        jubjub_params: &JubjubBn256,
        rns_params: &RnsParameters<Bn256, <Bn256 as JubjubEngine>::Fs>,
        crs: Crs<Bn256, CrsForMonomialForm>,
    ) -> Result<
        (
            VerificationKey<Bn256, DiscreteLogCircuit<Bn256>>,
            Proof<Bn256, DiscreteLogCircuit<Bn256>>,
        ),
        SynthesisError,
    > {
        let dummy_circuit = DiscreteLogCircuit::<Bn256> {
            base_point: None,
            coefficient: None,
            rns_params,
            jubjub_params,
        };

        let circuit = DiscreteLogCircuit::<Bn256> {
            base_point: Some(self.base_point.clone()),
            coefficient: Some(self.coefficient.clone()),
            rns_params,
            jubjub_params,
        };

        let mut dummy_assembly =
            SetupAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
        dummy_circuit
            .synthesize(&mut dummy_assembly)
            .expect("must synthesize");
        dummy_assembly.finalize();

        let worker = franklin_crypto::bellman::worker::Worker::new();
        let setup = dummy_assembly.create_setup::<DiscreteLogCircuit<Bn256>>(&worker)?;

        let vk =
            VerificationKey::<Bn256, DiscreteLogCircuit<Bn256>>::from_setup(&setup, &worker, &crs)?;

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
    .create_proof::<DiscreteLogCircuit<Bn256>, RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>>(
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
