// use franklin_crypto::bellman::plonk::commitments::transcript::{Prng, Transcript};
use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use franklin_crypto::bellman::{PrimeField, SynthesisError};
use franklin_crypto::plonk::circuit::allocated_num::AllocatedNum;
use franklin_crypto::plonk::circuit::bigint::field::FieldElement;
use franklin_crypto::plonk::circuit::boolean::AllocatedBit;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::WrappedAffinePoint;

use crate::circuit::poseidon::calc_poseidon;

use verkle_tree::ipa_fr::utils::{read_field_element_le, write_field_element_le};

pub trait Transcript<E: Engine>: Sized + Clone {
    type Params;

    fn new(init_state: Self::Params) -> Self;
    fn commit_alloc_num<CS: ConstraintSystem<E>>(
        &mut self,
        cs: &mut CS,
        element: AllocatedNum<E>,
    ) -> Result<(), SynthesisError>;
    fn commit_point<'a, CS: ConstraintSystem<E>, WP: WrappedAffinePoint<'a, E>>(
        &mut self,
        cs: &mut CS,
        point: &WP,
    ) -> Result<(), SynthesisError>;
    fn into_params(self) -> Self::Params;
    fn get_challenge(&mut self) -> AllocatedNum<E>;
}

#[derive(Clone)]
pub struct WrappedTranscript<E>
where
    E: Engine,
{
    // blake_2s_state: Blake2sTranscript<E::Fr>,
    state: AllocatedNum<E>,
    // _marker: PhantomData<CS>,
}

impl<E: Engine> Transcript<E> for WrappedTranscript<E> {
    type Params = AllocatedNum<E>;

    fn new(init_state: AllocatedNum<E>) -> Self {
        // let blake_2s_state = Blake2sTranscript::new();

        Self {
            // blake_2s_state,
            state: init_state,
            // _marker: std::marker::PhantomData,
        }
    }

    fn commit_alloc_num<CS: ConstraintSystem<E>>(
        &mut self,
        cs: &mut CS,
        element: AllocatedNum<E>,
    ) -> Result<(), SynthesisError> {
        let inputs = vec![self.state, element];
        self.state = calc_poseidon(cs, &inputs)?;

        Ok(())
    }

    fn get_challenge(&mut self) -> AllocatedNum<E> {
        self.state
    }

    fn commit_point<'a, CS: ConstraintSystem<E>, WP: WrappedAffinePoint<'a, E>>(
        &mut self,
        cs: &mut CS,
        point: &WP,
    ) -> Result<(), SynthesisError> {
        let unwrapped_point = point.get_point();
        let point_x = unwrapped_point.get_x();
        self.commit_field_element::<CS, E::Fq>(cs, point_x)?;
        let point_y = unwrapped_point.get_y();
        self.commit_field_element::<CS, E::Fq>(cs, point_y)?;

        Ok(())
    }

    fn into_params(self) -> Self::Params {
        self.state
    }
}

impl<E: Engine> WrappedTranscript<E> {
    // pub fn with_bytes(bytes: &[u8]) -> Self {
    //   let chunk_size = (E::Fr::NUM_BITS / 8) as usize;
    //   assert!(chunk_size != 0);
    //   assert!(bytes.len() <= chunk_size);
    //   let element = read_field_element_le::<E::Fr>(&bytes).unwrap();

    //   Self {
    //     state: element.clone(),
    //   }
    // }

    pub fn commit_bits<CS: ConstraintSystem<E>>(
        &mut self,
        cs: &mut CS,
        bytes: Vec<AllocatedBit>,
    ) -> Result<(), SynthesisError> {
        // TODO: constraint more strictly.
        let chunk_size = ((E::Fr::NUM_BITS / 8) * 8) as usize;
        assert!(chunk_size != 0);
        for b in bytes.chunks(chunk_size) {
            let value = b
                .iter()
                .map(|x| x.get_value())
                .collect::<Option<Vec<_>>>()
                .and_then(|x| {
                    let mut bytes = vec![];
                    for bits in x.chunks(8) {
                        let mut byte = if *bits.first().unwrap() { 1 } else { 0 };
                        let mut power = 1u8;
                        for b in bits.iter().skip(1) {
                            power *= 2;
                            if *b {
                                byte += power;
                            }
                        }

                        bytes.push(byte);
                    }

                    read_field_element_le::<E::Fr>(&bytes).ok()
                });
            let element = AllocatedNum::alloc(cs, || Ok(value.unwrap()))?;
            self.commit_alloc_num(cs, element)?;
        }

        // for b in bytes {
        //     let element = AllocatedNum::from_boolean_is(Boolean::from(b));
        //     self.commit_alloc_num(cs, element)?;
        // }

        Ok(())
    }

    pub fn commit_fr<CS: ConstraintSystem<E>>(
        &mut self,
        cs: &mut CS,
        element: Option<E::Fr>,
    ) -> Result<(), SynthesisError> {
        let input = AllocatedNum::alloc(cs, || Ok(element.unwrap()))?;
        self.commit_alloc_num(cs, input)?;

        Ok(())
    }

    pub fn commit_field_element<'a, CS: ConstraintSystem<E>, F: PrimeField>(
        &mut self,
        cs: &mut CS,
        element: FieldElement<'a, E, F>,
    ) -> Result<(), SynthesisError> {
        let value_bits = if let Some(value) = element.get_field_value() {
            write_field_element_le(&value)
                .iter()
                .flat_map(|x| {
                    let mut x_bits = vec![];
                    let mut y = *x;
                    for _ in 0..8 {
                        let a = AllocatedBit::alloc(cs, Some(y % 2 == 1));
                        x_bits.push(a);
                        y >>= 1;
                    }

                    x_bits
                })
                .collect::<Result<Vec<_>, SynthesisError>>()?
        } else {
            let mut value_bits = vec![];
            for _ in 0..F::NUM_BITS {
                value_bits.push(AllocatedBit::alloc(cs, None)?);
            }

            value_bits
        };

        self.commit_bits(cs, value_bits)?;

        Ok(())
    }

    pub fn commit_wrapped_affine<'a, CS: ConstraintSystem<E>, WP: WrappedAffinePoint<'a, E>>(
        &mut self,
        cs: &mut CS,
        element: WP,
    ) -> Result<(), SynthesisError> {
        self.commit_field_element(cs, element.get_point().get_x())?;
        self.commit_field_element(cs, element.get_point().get_y())?;

        Ok(())
    }
}
