use std::marker::PhantomData;

use franklin_crypto::bellman::pairing::ff::Field;
use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::{Circuit, ConstraintSystem, SynthesisError};
use franklin_crypto::circuit::boolean::{AllocatedBit, Boolean};
use franklin_crypto::circuit::num::AllocatedNum;

// the circuit to prove a prover knows `inputs` that `output` is equal to the logical AND of
// `inputs[0]` and `inputs[1]`
pub struct SampleCircuit<E: Engine> {
  pub inputs: [Option<bool>; 2],
  pub _e: PhantomData<E>,
}

impl<E: Engine> Circuit<E> for SampleCircuit<E> {
  fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
    // `inputs[0]` and `inputs[1]` are boolean values.
    let inputs = self
      .inputs
      .into_iter()
      .enumerate()
      .map(|(i, bit)| {
        AllocatedBit::alloc(cs.namespace(|| format!("allocated inputs: {}", i)), bit).unwrap()
      })
      .collect::<Vec<_>>();

    // `output` is the logical AND of `inputs[0]` and `inputs[1]`.
    let output = AllocatedBit::and(cs.namespace(|| "and"), &inputs[0], &inputs[1])?;

    // Convert `output` to `output_fr`.
    let one = AllocatedNum::<E>::alloc(cs.namespace(|| "one"), || Ok(E::Fr::one()))?;
    let zero = AllocatedNum::<E>::alloc(cs.namespace(|| "zero"), || Ok(E::Fr::zero()))?;
    let output_fr = AllocatedNum::conditionally_select(
      cs.namespace(|| "output_fr"),
      &one,
      &zero,
      &Boolean::from(output),
    )?;

    // `output` is a public variable, while `inputs[0]` and `inputs[1]` are private variables.
    output_fr.inputize(cs.namespace(|| "public output"))?;

    Ok(())
  }
}

impl<E: Engine> SampleCircuit<E> {
  pub fn get_public_wires(&self) -> anyhow::Result<Vec<E::Fr>> {
    let inputs = self.inputs;
    let output: E::Fr = if inputs[0].unwrap() && inputs[1].unwrap() {
      E::Fr::one()
    } else {
      E::Fr::zero()
    };

    Ok(vec![output])
  }
}
