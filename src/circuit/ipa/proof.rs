use franklin_crypto::bellman::{ConstraintSystem, SynthesisError};
// use franklin_crypto::circuit::ecc::EdwardsPoint;
use franklin_crypto::circuit::num::AllocatedNum;
use franklin_crypto::jubjub::JubjubEngine;
// use franklin_crypto::plonk::circuit::verifier_circuit::channel::ChannelGadget;
// use franklin_crypto::rescue::rescue_transcript::RescueTranscriptForRNS;
// use franklin_crypto::rescue::RescueEngine;

use super::transcript::Transcript;

#[derive(Clone, Debug)]
pub struct IpaProof<E: JubjubEngine> {
    pub l: Vec<(E::Fr, E::Fr)>,
    pub r: Vec<(E::Fr, E::Fr)>,
    pub a: E::Fr,
}

#[derive(Clone)]
pub struct OptionIpaProof<E: JubjubEngine> {
    pub l: Vec<Option<(E::Fr, E::Fr)>>,
    pub r: Vec<Option<(E::Fr, E::Fr)>>,
    pub a: Option<E::Fr>,
}

impl<E: JubjubEngine> OptionIpaProof<E> {
    pub fn with_depth(depth: usize) -> Self {
        Self {
            l: vec![None; depth],
            r: vec![None; depth],
            a: None,
        }
    }
}

impl<E: JubjubEngine> From<IpaProof<E>> for OptionIpaProof<E> {
    fn from(ipa_proof: IpaProof<E>) -> Self {
        Self {
            l: ipa_proof
                .l
                .iter()
                .map(|&(l1, l2)| Some((l1, l2)))
                .collect::<Vec<_>>(),
            r: ipa_proof
                .r
                .iter()
                .map(|&(r1, r2)| Some((r1, r2)))
                .collect::<Vec<_>>(),
            a: Some(ipa_proof.a),
        }
    }
}

pub fn generate_challenges<'a, E: JubjubEngine, CS: ConstraintSystem<E>, T: Transcript<E>>(
    cs: &mut CS,
    ipa_proof: &OptionIpaProof<E>,
    transcript: &mut T,
) -> Result<Vec<AllocatedNum<E>>, SynthesisError> {
    let mut challenges: Vec<AllocatedNum<E>> = Vec::with_capacity(ipa_proof.l.len());
    for (l, r) in ipa_proof.l.iter().zip(&ipa_proof.r) {
        // let wrapped_l = EdwardsPoint::interpret(
        //   cs,
        //   &AllocatedNum::alloc(cs, || Ok(l.0.unwrap()))?,
        //   &AllocatedNum::alloc(cs, || Ok(l.1.unwrap()))?,
        //   jubjub_params,
        // )?;
        // let wrapped_r = EdwardsPoint::interpret(
        //   cs,
        //   &AllocatedNum::alloc(cs, || Ok(r.0.unwrap()))?,
        //   &AllocatedNum::alloc(cs, || Ok(r.1.unwrap()))?,
        //   jubjub_params,
        // )?;
        // transcript.consume_point(cs, wrapped_l)?; // L
        // transcript.consume_point(cs, wrapped_r)?; // R

        transcript.commit_field_element(cs, &l.map(|p| p.0))?;
        transcript.commit_field_element(cs, &l.map(|p| p.1))?;
        transcript.commit_field_element(cs, &r.map(|p| p.0))?;
        transcript.commit_field_element(cs, &r.map(|p| p.1))?;
        // transcript.commit_field_element(&l.0.unwrap()); // L[i]_x
        // transcript.commit_field_element(&l.1.unwrap()); // L[i]_y
        // transcript.commit_field_element(&r.0.unwrap()); // R[i]_x
        // transcript.commit_field_element(&l.1.unwrap()); // R[i]_y

        let challenge = transcript.get_challenge();
        let c: AllocatedNum<E> = AllocatedNum::alloc(cs.namespace(|| "alloc challenge"), || {
            challenge.ok_or(SynthesisError::Unsatisfiable)
        })?;
        challenges.push(c);
    }

    Ok(challenges)
}
