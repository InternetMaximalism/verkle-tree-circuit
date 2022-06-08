extern crate wasm_bindgen;

// use generic_array::typenum::Unsigned;
// use neptune::{poseidon::PoseidonConstants, Poseidon};
// use verkle_tree::{ff::Field, ff_utils::bn256_fr::Bn256Fr};
use wasm_bindgen::prelude::*;

// use crate::utils::{read_field_element_le, write_field_element_be};

// fn poseidon(args: Vec<String>) -> String {
//     type Arity = generic_array::typenum::U2;

//     let mut preimage = vec![<Bn256Fr as Field>::zero(); Arity::to_usize()];
//     for (i, input) in preimage.iter_mut().enumerate() {
//         let mut arg_bytes = hex::decode(&args[i]).expect("fail to convert arguments");
//         arg_bytes.reverse();

//         let _ = std::mem::replace(
//             input,
//             read_field_element_le::<Bn256Fr>(&arg_bytes).expect("fail to convert field element"),
//         );
//     }

//     let constants = PoseidonConstants::new(); // TODO: Use cache
//     let mut h = Poseidon::<Bn256Fr, Arity>::new_with_preimage(&preimage, &constants);
//     let output = h.hash();
//     let data = write_field_element_be::<Bn256Fr>(&output);
//     let output_hex = hex::encode(&data);

//     output_hex
// }

#[wasm_bindgen]
extern "C" {
    pub fn alert(s: &str);
}

#[wasm_bindgen]
pub fn poseidon_t3(input1: &str) -> String {
    // let inputs = vec![input1.to_string(), input2.to_string()];
    // poseidon(inputs)
    String::from(input1) // + input2
}

// pub mod utils;
