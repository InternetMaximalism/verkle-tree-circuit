use generic_array::typenum::Unsigned;
use neon::prelude::*;
use neptune::{poseidon::PoseidonConstants, Poseidon};
use verkle_tree::{ff::Field, ff_utils::bn256_fr::Bn256Fr};

use crate::utils::{read_field_element_le, write_field_element_be};

fn poseidon_t3(mut cx: FunctionContext) -> JsResult<JsString> {
    type Arity = generic_array::typenum::U2;

    let mut preimage = vec![<Bn256Fr as Field>::zero(); Arity::to_usize()];
    for (i, input) in preimage.iter_mut().enumerate() {
        let arg = cx.argument::<JsString>(i as i32)?;
        let mut arg_bytes = hex::decode(&arg.value(&mut cx)).expect("fail to convert arguments");
        arg_bytes.reverse();

        let _ = std::mem::replace(
            input,
            read_field_element_le::<Bn256Fr>(&arg_bytes).expect("fail to convert field element"),
        );
    }

    let constants = PoseidonConstants::new(); // TODO: Use cache
    let mut h = Poseidon::<Bn256Fr, Arity>::new_with_preimage(&preimage, &constants);
    let output = h.hash();
    let data = write_field_element_be::<Bn256Fr>(&output);
    let output_hex = hex::encode(&data);

    Ok(cx.string(&output_hex))
}

fn hello(mut cx: FunctionContext) -> JsResult<JsString> {
    Ok(cx.string("hello neon"))
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("hello", hello)?;
    cx.export_function("poseidon_t3", poseidon_t3)?;
    Ok(())
}

pub mod utils;
