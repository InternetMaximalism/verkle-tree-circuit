pub mod input;
pub mod run;

#[test]
fn test_discrete_log_circuit() -> Result<(), Box<dyn std::error::Error>> {
    use franklin_crypto::babyjubjub::fs::{Fs, FsRepr};
    use franklin_crypto::babyjubjub::{edwards, JubjubBn256, Unknown};
    use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr, FrRepr};
    use franklin_crypto::bellman::{PrimeField, PrimeFieldRepr};

    use crate::api::discrete_log::input::CircuitInput;
    use crate::api::discrete_log::run::run;

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
    let jubjub_params = JubjubBn256::new();
    let base_point = edwards::Point::<Bn256, Unknown>::get_for_y(
        base_point_y,
        base_point_x.into_repr().is_odd(),
        &jubjub_params,
    )
    .unwrap();
    let output = base_point.mul(coefficient, &jubjub_params);
    assert_eq!(output.into_xy(), (output_x, output_y));
    let circuit_input = CircuitInput {
        base_point_x: Some(base_point_x),
        base_point_y: Some(base_point_y),
        coefficient: Some(coefficient),
    };
    run(circuit_input)?;

    Ok(())
}
