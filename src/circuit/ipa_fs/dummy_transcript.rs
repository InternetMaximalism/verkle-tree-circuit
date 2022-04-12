use franklin_crypto::{
    babyjubjub::JubjubEngine,
    bellman::{
        plonk::commitments::transcript::{Blake2sTranscript, Prng, Transcript},
        ConstraintSystem, SynthesisError,
    },
};

use super::transcript::Transcript as TranscriptCircuit;

#[derive(Clone)]
pub struct WrappedTranscript<E: JubjubEngine> {
    pub state: Blake2sTranscript<E::Fr>,
}

impl<'a, E: JubjubEngine> TranscriptCircuit<'a, E> for WrappedTranscript<E> {
    fn new(_init_state: Option<E::Fr>) -> Self {
        let state = Blake2sTranscript::new();

        Self { state }
    }

    fn commit_field_element<CS: ConstraintSystem<E>>(
        &mut self,
        _cs: &mut CS,
        element: &Option<E::Fr>,
    ) -> Result<(), SynthesisError> {
        if let Some(elt) = element {
            self.state.commit_field_element(elt)
        }

        Ok(())
    }

    fn get_challenge(&mut self) -> Option<E::Fr> {
        let value = self.state.get_challenge();

        Some(value)
    }
}
