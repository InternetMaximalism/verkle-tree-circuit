pub mod input;
pub mod run;

// #[test]
// fn test_discrete_log_circuit() -> Result<(), Box<dyn std::error::Error>> {
//     use franklin_crypto::bellman::pairing::bn256::{Fr, FrRepr};
//     use franklin_crypto::bellman::pairing::ff::PrimeField;

//     use crate::api::discrete_log::input::CircuitInput;
//     use crate::api::discrete_log::run::run;

//     let base_point_x = Fr::from_repr(FrRepr([
//         0x2893f3f6bb957051u64,
//         0x2ab8d8010534e0b6,
//         0x4eacb2e09d6277c1,
//         0x0bb77a6ad63e739b,
//     ]))?;
//     let base_point_y = Fr::from_repr(FrRepr([
//         0x4b3c257a872d7d8bu64,
//         0xfce0051fb9e13377,
//         0x25572e1cd16bf9ed,
//         0x25797203f7a0b249,
//     ]))?;
//     let coefficient = Fr::from_repr(FrRepr([4u64, 3, 2, 1]))?;
//     let circuit_input = CircuitInput {
//         base_point_x: Some(base_point_x),
//         base_point_y: Some(base_point_y),
//         coefficient: Some(coefficient),
//     };
//     run(circuit_input)?;

//     Ok(())
// }
