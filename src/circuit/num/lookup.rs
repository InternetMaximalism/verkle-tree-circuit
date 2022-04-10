use franklin_crypto::{
    bellman::{
        pairing::{ff::Field, Engine},
        plonk::better_better_cs::cs::{ArithmeticTerm, ConstraintSystem, MainGateTerm},
        SynthesisError,
    },
    plonk::circuit::{
        allocated_num::{AllocatedNum, Num},
        assignment::Assignment,
        boolean::Boolean,
    },
};

// Synthesize the constants for each base pattern.
fn synth<'a, E: Engine, I>(window_size: usize, constants: I, assignment: &mut [E::Fr])
where
    I: IntoIterator<Item = &'a E::Fr>,
{
    assert_eq!(assignment.len(), 1 << window_size);

    for (i, constant) in constants.into_iter().enumerate() {
        let mut cur = assignment[i];
        cur.negate();
        cur.add_assign(constant);
        assignment[i] = cur;
        for (j, eval) in assignment.iter_mut().enumerate().skip(i + 1) {
            if j & i == i {
                eval.add_assign(&cur);
            }
        }
    }
}

/// Performs a 3-bit window table lookup. `bits` is in
/// little-endian order.
pub fn lookup3_xy<E: Engine, CS>(
    cs: &mut CS,
    bits: &[Boolean],
    coords: &[(E::Fr, E::Fr)],
) -> Result<(AllocatedNum<E>, AllocatedNum<E>), SynthesisError>
where
    CS: ConstraintSystem<E>,
{
    assert_eq!(bits.len(), 3);
    assert_eq!(coords.len(), 8);

    // Calculate the index into `coords`
    let i = match (
        bits[0].get_value(),
        bits[1].get_value(),
        bits[2].get_value(),
    ) {
        (Some(a_value), Some(b_value), Some(c_value)) => {
            let mut tmp = 0;
            if a_value {
                tmp += 1;
            }
            if b_value {
                tmp += 2;
            }
            if c_value {
                tmp += 4;
            }
            Some(tmp)
        }
        _ => None,
    };

    // Allocate the x-coordinate resulting from the lookup
    let res_x = AllocatedNum::alloc(cs, || Ok(coords[*i.get()?].0))?;

    // Allocate the y-coordinate resulting from the lookup
    let res_y = AllocatedNum::alloc(cs, || Ok(coords[*i.get()?].1))?;

    // Compute the coefficients for the lookup constraints
    let mut x_coeffs = [E::Fr::zero(); 8];
    let mut y_coeffs = [E::Fr::zero(); 8];
    synth::<E, _>(3, coords.iter().map(|c| &c.0), &mut x_coeffs);
    synth::<E, _>(3, coords.iter().map(|c| &c.1), &mut y_coeffs);

    let precomp = Boolean::and(cs, &bits[1], &bits[2])?;

    // let one = CS::one();
    let one = AllocatedNum::one(cs);
    let zero = AllocatedNum::zero(cs);

    // left = x_coeffs[0b001] + bits[1] ? x_coeffs[0b011] : 0 + bits[2] ? x_coeffs[0b101] : 0 + precomp ? x_coeffs[0b111] : 0
    // right = bits[0] ? 1 : 0
    // output = res_x - x_coeffs[0b000] - bits[1] ? x_coeffs[0b010] : 0 - bits[2] ? x_coeffs[0b100] : 0 - precomp ? x_coeffs[0b110] : 0
    // cs.enforce(
    //     || "x-coordinate lookup",
    //     |lc| {
    //         lc + (x_coeffs[0b001], one)
    //             + &bits[1].lc::<E>(x_coeffs[0b011])
    //             + &bits[2].lc::<E>(x_coeffs[0b101])
    //             + &precomp.lc::<E>(x_coeffs[0b111])
    //     },
    //     |lc| lc + &bits[0].lc::<E>(E::Fr::one()),
    //     |lc| {
    //         lc + res_x.get_variable()
    //             - (x_coeffs[0b000], one)
    //             - &bits[1].lc::<E>(x_coeffs[0b010])
    //             - &bits[2].lc::<E>(x_coeffs[0b100])
    //             - &precomp.lc::<E>(x_coeffs[0b110])
    //     },
    // );
    {
        let x_coeffs_1 = AllocatedNum::alloc(cs, || Ok(x_coeffs[0b001]))?;
        let x_coeffs_1_term = ArithmeticTerm::<E>::from_variable(x_coeffs_1.get_variable());
        let x_coeffs_3 = AllocatedNum::alloc(cs, || Ok(x_coeffs[0b011]))?;
        let select_1 = AllocatedNum::conditionally_select(cs, &x_coeffs_3, &zero, &bits[1])?;
        let select_1_term = ArithmeticTerm::<E>::from_variable(select_1.get_variable());
        let x_coeffs_5 = AllocatedNum::alloc(cs, || Ok(x_coeffs[0b101]))?;
        let select_2 = AllocatedNum::conditionally_select(cs, &x_coeffs_5, &zero, &bits[2])?;
        let select_2_term = ArithmeticTerm::<E>::from_variable(select_2.get_variable());
        let x_coeffs_7 = AllocatedNum::alloc(cs, || Ok(x_coeffs[0b111]))?;
        let select_3 = AllocatedNum::conditionally_select(cs, &x_coeffs_7, &zero, &precomp)?;
        let select_3_term = ArithmeticTerm::<E>::from_variable(select_3.get_variable());
        let left = res_x
            .sub(cs, &x_coeffs_1)?
            .sub(cs, &select_1)?
            .add(cs, &select_2)?
            .add(cs, &select_3)?;
        let left_term = ArithmeticTerm::<E>::from_variable(left.get_variable());

        let mut term1 = MainGateTerm::new();
        term1.add_assign(x_coeffs_1_term);
        term1.add_assign(select_1_term);
        term1.add_assign(select_2_term);
        term1.add_assign(select_3_term);
        term1.sub_assign(left_term.clone());
        cs.allocate_main_gate(term1)?;

        let right_select = AllocatedNum::conditionally_select(cs, &one, &zero, &bits[0])?;

        // output = res_x - x_coeffs[0b000] - bits[1] ? x_coeffs[0b010] : 0 + bits[2] ? x_coeffs[0b100] : 0 + precomp ? x_coeffs[0b110] : 0
        let res_x_term = ArithmeticTerm::<E>::from_variable(res_x.get_variable());
        let x_coeffs_0 = AllocatedNum::alloc(cs, || Ok(x_coeffs[0b000]))?;
        let x_coeffs_0_term = ArithmeticTerm::<E>::from_variable(x_coeffs_0.get_variable());
        let x_coeffs_2 = AllocatedNum::alloc(cs, || Ok(x_coeffs[0b010]))?;
        let select_1 = AllocatedNum::conditionally_select(cs, &x_coeffs_2, &zero, &bits[1])?;
        let select_1_term = ArithmeticTerm::<E>::from_variable(select_1.get_variable());
        let x_coeffs_4 = AllocatedNum::alloc(cs, || Ok(x_coeffs[0b100]))?;
        let select_2 = AllocatedNum::conditionally_select(cs, &x_coeffs_4, &zero, &bits[2])?;
        let select_2_term = ArithmeticTerm::<E>::from_variable(select_2.get_variable());
        let x_coeffs_6 = AllocatedNum::alloc(cs, || Ok(x_coeffs[0b110]))?;
        let select_3 = AllocatedNum::conditionally_select(cs, &x_coeffs_6, &zero, &precomp)?;
        let select_3_term = ArithmeticTerm::<E>::from_variable(select_3.get_variable());
        let output = res_x
            .sub(cs, &x_coeffs_0)?
            .sub(cs, &select_1)?
            .add(cs, &select_2)?
            .add(cs, &select_3)?;
        let output_term = ArithmeticTerm::<E>::from_variable(output.get_variable());

        let mut term3 = MainGateTerm::new();
        term3.add_assign(res_x_term);
        term3.sub_assign(x_coeffs_0_term);
        term3.sub_assign(select_1_term);
        term3.sub_assign(select_2_term);
        term3.sub_assign(select_3_term);
        term3.sub_assign(output_term.clone());
        cs.allocate_main_gate(term3)?;

        let mut term = MainGateTerm::new();
        term.add_assign(left_term.mul_by_variable(right_select.get_variable()));
        term.sub_assign(output_term);
        cs.allocate_main_gate(term)?;
    }

    // left = y_coeffs[0b001] + bits[1] ? y_coeffs[0b011] : 0 + bits[2] ? y_coeffs[0b101] : 0 + precomp ? y_coeffs[0b111] : 0
    // right = bits[0] ? 1 : 0
    // output = res_y - y_coeffs[0b000] + bits[1] ? y_coeffs[0b010] : 0 - bits[2] ? y_coeffs[0b100] : 0 - precomp ? y_coeffs[0b110] : 0
    // cs.enforce(
    //     || "y-coordinate lookup",
    //     |lc| {
    //         lc + (y_coeffs[0b001], one)
    //             + &bits[1].lc::<E>(y_coeffs[0b011])
    //             + &bits[2].lc::<E>(y_coeffs[0b101])
    //             + &precomp.lc::<E>(y_coeffs[0b111])
    //     },
    //     |lc| lc + &bits[0].lc::<E>(E::Fr::one()),
    //     |lc| {
    //         lc + res_y.get_variable()
    //             - (y_coeffs[0b000], one)
    //             - &bits[1].lc::<E>(y_coeffs[0b010])
    //             - &bits[2].lc::<E>(y_coeffs[0b100])
    //             - &precomp.lc::<E>(y_coeffs[0b110])
    //     },
    // );
    {
        let y_coeffs_1 = AllocatedNum::alloc(cs, || Ok(y_coeffs[0b001]))?;
        let y_coeffs_1_term = ArithmeticTerm::<E>::from_variable(y_coeffs_1.get_variable());
        let y_coeffs_3 = AllocatedNum::alloc(cs, || Ok(y_coeffs[0b011]))?;
        let select_1 = AllocatedNum::conditionally_select(cs, &y_coeffs_3, &zero, &bits[1])?;
        let select_1_term = ArithmeticTerm::<E>::from_variable(select_1.get_variable());
        let y_coeffs_5 = AllocatedNum::alloc(cs, || Ok(y_coeffs[0b101]))?;
        let select_2 = AllocatedNum::conditionally_select(cs, &y_coeffs_5, &zero, &bits[2])?;
        let select_2_term = ArithmeticTerm::<E>::from_variable(select_2.get_variable());
        let y_coeffs_7 = AllocatedNum::alloc(cs, || Ok(y_coeffs[0b111]))?;
        let select_3 = AllocatedNum::conditionally_select(cs, &y_coeffs_7, &zero, &precomp)?;
        let select_3_term = ArithmeticTerm::<E>::from_variable(select_3.get_variable());
        let left = res_x
            .sub(cs, &y_coeffs_1)?
            .sub(cs, &select_1)?
            .add(cs, &select_2)?
            .add(cs, &select_3)?;
        let left_term = ArithmeticTerm::<E>::from_variable(left.get_variable());

        let mut term1 = MainGateTerm::new();
        term1.add_assign(y_coeffs_1_term);
        term1.add_assign(select_1_term);
        term1.add_assign(select_2_term);
        term1.add_assign(select_3_term);
        term1.sub_assign(left_term.clone());
        cs.allocate_main_gate(term1)?;

        let right_select = AllocatedNum::conditionally_select(cs, &one, &zero, &bits[0])?;

        let res_y_term = ArithmeticTerm::<E>::from_variable(res_y.get_variable());
        let y_coeffs_0 = AllocatedNum::alloc(cs, || Ok(y_coeffs[0b000]))?;
        let y_coeffs_0_term = ArithmeticTerm::<E>::from_variable(y_coeffs_0.get_variable());
        let y_coeffs_2 = AllocatedNum::alloc(cs, || Ok(y_coeffs[0b010]))?;
        let select_1 = AllocatedNum::conditionally_select(cs, &y_coeffs_2, &zero, &bits[1])?;
        let select_1_term = ArithmeticTerm::<E>::from_variable(select_1.get_variable());
        let y_coeffs_4 = AllocatedNum::alloc(cs, || Ok(y_coeffs[0b100]))?;
        let select_2 = AllocatedNum::conditionally_select(cs, &y_coeffs_4, &zero, &bits[2])?;
        let select_2_term = ArithmeticTerm::<E>::from_variable(select_2.get_variable());
        let y_coeffs_6 = AllocatedNum::alloc(cs, || Ok(y_coeffs[0b110]))?;
        let select_3 = AllocatedNum::conditionally_select(cs, &y_coeffs_6, &zero, &precomp)?;
        let select_3_term = ArithmeticTerm::<E>::from_variable(select_3.get_variable());
        let output = res_y
            .sub(cs, &y_coeffs_0)?
            .sub(cs, &select_1)?
            .add(cs, &select_2)?
            .add(cs, &select_3)?;
        let output_term = ArithmeticTerm::<E>::from_variable(output.get_variable());

        let mut term3 = MainGateTerm::new();
        term3.add_assign(res_y_term);
        term3.sub_assign(y_coeffs_0_term);
        term3.sub_assign(select_1_term);
        term3.sub_assign(select_2_term);
        term3.sub_assign(select_3_term);
        term3.sub_assign(output_term.clone());
        cs.allocate_main_gate(term3)?;

        let mut term = MainGateTerm::new();
        term.add_assign(left_term.mul_by_variable(right_select.get_variable()));
        term.sub_assign(output_term);
    }

    Ok((res_x, res_y))
}

/// Performs a 3-bit window table lookup, where
/// one of the bits is a sign bit.
pub fn lookup3_xy_with_conditional_negation<E: Engine, CS>(
    cs: &mut CS,
    bits: &[Boolean],
    coords: &[(E::Fr, E::Fr)],
) -> Result<(Num<E>, Num<E>), SynthesisError>
where
    CS: ConstraintSystem<E>,
{
    assert_eq!(bits.len(), 3);
    assert_eq!(coords.len(), 4);

    // Calculate the index into `coords`
    let i = match (bits[0].get_value(), bits[1].get_value()) {
        (Some(a_value), Some(b_value)) => {
            let mut tmp = 0;
            if a_value {
                tmp += 1;
            }
            if b_value {
                tmp += 2;
            }
            Some(tmp)
        }
        _ => None,
    };

    // Allocate the y-coordinate resulting from the lookup
    // and conditional negation
    let y = AllocatedNum::alloc(cs, || {
        let mut tmp = coords[*i.get()?].1;
        if *bits[2].get_value().get()? {
            tmp.negate();
        }
        Ok(tmp)
    })?;

    // let one = CS::one();

    // Compute the coefficients for the lookup constraints
    let mut x_coeffs = [E::Fr::zero(); 4];
    let mut y_coeffs = [E::Fr::zero(); 4];
    synth::<E, _>(2, coords.iter().map(|c| &c.0), &mut x_coeffs);
    synth::<E, _>(2, coords.iter().map(|c| &c.1), &mut y_coeffs);

    let precomp = Boolean::and(cs, &bits[0], &bits[1])?;

    // x_lc = x_coeffs[0b00] + bits[0] ? x_coeffs[0b01] : 0 + bits[1] ? x_coeffs[0b10] : 0 + precomp ? x_coeffs[0b11] : 0
    // let x_lc = Num::lc(cs, &[], &[])?
    //     .add_bool_with_coeff(one, &Boolean::constant(true), x_coeffs[0b00])
    //     .add_bool_with_coeff(one, &bits[0], x_coeffs[0b01])
    //     .add_bool_with_coeff(one, &bits[1], x_coeffs[0b10])
    //     .add_bool_with_coeff(one, &precomp, x_coeffs[0b11]);
    let zero = AllocatedNum::zero(cs);
    let x_coeffs_3 = AllocatedNum::alloc(cs, || Ok(x_coeffs[0b11]))?;
    let select_1 = AllocatedNum::conditionally_select(cs, &x_coeffs_3, &zero, &precomp)?;
    let x_coeffs_2 = AllocatedNum::alloc(cs, || Ok(x_coeffs[0b10]))?;
    let select_2 = AllocatedNum::conditionally_select(cs, &x_coeffs_2, &zero, &bits[1])?;
    let x_coeffs_1 = AllocatedNum::alloc(cs, || Ok(x_coeffs[0b01]))?;
    let select_3 = AllocatedNum::conditionally_select(cs, &x_coeffs_1, &zero, &bits[0])?;
    let x_coeffs_0 = AllocatedNum::alloc(cs, || Ok(x_coeffs[0b01]))?;

    let x_lc = select_1
        .add(cs, &select_2)?
        .add(cs, &select_3)?
        .add(cs, &x_coeffs_0)?;

    // y_lc = precomp ? y_coeffs[0b11] : 0 + bits[1] ? y_coeffs[0b10] : 0 + bits[0] ? y_coeffs[0b01] : 0 + y_coeffs[0b00]
    // let y_lc = precomp.lc::<E>(y_coeffs[0b11])
    //     + &bits[1].lc::<E>(y_coeffs[0b10])
    //     + &bits[0].lc::<E>(y_coeffs[0b01])
    //     + (y_coeffs[0b00], one);
    let zero = AllocatedNum::zero(cs);
    let y_coeffs_3 = AllocatedNum::alloc(cs, || Ok(y_coeffs[0b11]))?;
    let select_1 = AllocatedNum::conditionally_select(cs, &y_coeffs_3, &zero, &precomp)?;
    let y_coeffs_2 = AllocatedNum::alloc(cs, || Ok(y_coeffs[0b10]))?;
    let select_2 = AllocatedNum::conditionally_select(cs, &y_coeffs_2, &zero, &bits[1])?;
    let y_coeffs_1 = AllocatedNum::alloc(cs, || Ok(y_coeffs[0b01]))?;
    let select_3 = AllocatedNum::conditionally_select(cs, &y_coeffs_1, &zero, &bits[0])?;
    let y_coeffs_0 = AllocatedNum::alloc(cs, || Ok(y_coeffs[0b01]))?;

    let y_lc = select_1
        .add(cs, &select_2)?
        .add(cs, &select_3)?
        .add(cs, &y_coeffs_0)?;

    // y = bits[2] ? -y_lc : y_lc
    // cs.enforce(
    //     || "y-coordinate lookup",
    //     |lc| lc + &y_lc + &y_lc,
    //     |lc| lc + &bits[2].lc::<E>(one, E::Fr::one()),
    //     |lc| lc + &y_lc - y.get_variable(),
    // );
    {
        let y_lc_plus_y_lc = y_lc.add(cs, &y_lc)?;
        let result = AllocatedNum::conditionally_select(cs, &y_lc_plus_y_lc, &zero, &bits[2])?
            .sub(cs, &y_lc)?
            .add(cs, &y)?;
        result.assert_is_zero(cs)?;
    }

    Ok((Num::Variable(x_lc), Num::Variable(y)))
}

// #[cfg(test)]
// mod test {
//     use franklin_crypto::{
//         bellman::pairing::bls12_381::{Bls12, Fr},
//         circuit::test::*,
//         plonk::circuit::boolean::{AllocatedBit, Boolean},
//     };
//     use rand::{Rand, Rng, SeedableRng, XorShiftRng};

//     use super::lookup3_xy;

//     #[test]
//     fn test_lookup3_xy() {
//         let mut rng = XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0656]);

//         for _ in 0..100 {
//             let mut cs = &mut TestConstraintSystem::<Bls12>::new();

//             let a_val = rng.gen();
//             let a = Boolean::from(AllocatedBit::alloc(cs, Some(a_val)).unwrap());

//             let b_val = rng.gen();
//             let b = Boolean::from(AllocatedBit::alloc(cs, Some(b_val)).unwrap());

//             let c_val = rng.gen();
//             let c = Boolean::from(AllocatedBit::alloc(cs, Some(c_val)).unwrap());

//             let bits = vec![a, b, c];

//             let points: Vec<(Fr, Fr)> = (0..8).map(|_| (rng.gen(), rng.gen())).collect();

//             let res = lookup3_xy(cs, &bits, &points).unwrap();

//             assert!(cs.is_satisfied());

//             let mut index = 0;
//             if a_val {
//                 index += 1
//             }
//             if b_val {
//                 index += 2
//             }
//             if c_val {
//                 index += 4
//             }

//             assert_eq!(res.0.get_value().unwrap(), points[index].0);
//             assert_eq!(res.1.get_value().unwrap(), points[index].1);
//         }
//     }

//     #[test]
//     fn test_lookup3_xy_with_conditional_negation() {
//         let mut rng = XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

//         for _ in 0..100 {
//             let mut cs = TestConstraintSystem::<Bls12>::new();

//             let a_val = rng.gen();
//             let a = Boolean::from(AllocatedBit::alloc(cs.namespace(|| "a"), Some(a_val)).unwrap());

//             let b_val = rng.gen();
//             let b = Boolean::from(AllocatedBit::alloc(cs.namespace(|| "b"), Some(b_val)).unwrap());

//             let c_val = rng.gen();
//             let c = Boolean::from(AllocatedBit::alloc(cs.namespace(|| "c"), Some(c_val)).unwrap());

//             let bits = vec![a, b, c];

//             let points: Vec<(Fr, Fr)> = (0..4).map(|_| (rng.gen(), rng.gen())).collect();

//             let res = lookup3_xy_with_conditional_negation(&mut cs, &bits, &points).unwrap();

//             assert!(cs.is_satisfied());

//             let mut index = 0;
//             if a_val {
//                 index += 1
//             }
//             if b_val {
//                 index += 2
//             }

//             assert_eq!(res.0.get_value().unwrap(), points[index].0);
//             let mut tmp = points[index].1;
//             if c_val {
//                 tmp.negate()
//             }
//             assert_eq!(res.1.get_value().unwrap(), tmp);
//         }
//     }

//     #[test]
//     fn test_synth() {
//         let mut rng = XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

//         let window_size = 4;

//         let mut assignment = vec![Fr::zero(); 1 << window_size];
//         let constants: Vec<_> = (0..(1 << window_size))
//             .map(|_| Fr::rand(&mut rng))
//             .collect();

//         synth::<Bls12, _>(window_size, &constants, &mut assignment);

//         for b in 0..(1 << window_size) {
//             let mut acc = Fr::zero();

//             for j in 0..(1 << window_size) {
//                 if j & b == j {
//                     acc.add_assign(&assignment[j]);
//                 }
//             }

//             assert_eq!(acc, constants[b]);
//         }
//     }
// }
