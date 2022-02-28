use franklin_crypto::bellman::{CurveAffine, SynthesisError};
// use franklin_crypto::circuit::ecc::EdwardsPoint;
use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use franklin_crypto::plonk::circuit::allocated_num::AllocatedNum;
use franklin_crypto::plonk::circuit::bigint::field::RnsParameters;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::aux_data::AuxData;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::WrappedAffinePoint;
use verkle_tree::ipa_fr::proof::IpaProof;

use super::transcript::{Transcript, WrappedTranscript};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OptionIpaProof<GA: CurveAffine> {
    pub l: Vec<Option<GA>>,
    pub r: Vec<Option<GA>>,
    pub a: Option<GA::Scalar>,
}

impl<GA: CurveAffine> OptionIpaProof<GA> {
    pub fn with_depth(depth: usize) -> Self {
        Self {
            l: vec![None; depth],
            r: vec![None; depth],
            a: None,
        }
    }
    pub fn take(&mut self) -> Self {
        let l = self.l.iter_mut().map(Option::take).collect::<Vec<_>>();
        let r = self.r.iter_mut().map(Option::take).collect::<Vec<_>>();
        let a = self.a.take();

        Self { l, r, a }
    }
}

impl<GA: CurveAffine> From<IpaProof<GA>> for OptionIpaProof<GA> {
    fn from(ipa_proof: IpaProof<GA>) -> Self {
        Self {
            l: ipa_proof.l.iter().map(|&l| Some(l)).collect::<Vec<_>>(),
            r: ipa_proof.r.iter().map(|&r| Some(r)).collect::<Vec<_>>(),
            a: Some(ipa_proof.a),
        }
    }
}

pub fn generate_challenges<
    'a,
    E: Engine,
    CS: ConstraintSystem<E>,
    WP: WrappedAffinePoint<'a, E>,
    AD: AuxData<E>,
>(
    cs: &mut CS,
    ipa_proof: OptionIpaProof<E::G1Affine>,
    transcript: &mut WrappedTranscript<E>,
    rns_params: &'a RnsParameters<E, <E::G1Affine as CurveAffine>::Base>,
    aux_data: &AD,
) -> Result<Vec<AllocatedNum<E>>, SynthesisError> {
    let mut challenges: Vec<AllocatedNum<E>> = Vec::with_capacity(ipa_proof.l.len());
    for (&l, &r) in ipa_proof.l.iter().zip(&ipa_proof.r) {
        let wrapped_l = WP::alloc(cs, l, rns_params, aux_data)?;
        let wrapped_r = WP::alloc(cs, r, rns_params, aux_data)?;
        transcript.commit_wrapped_affine(cs, wrapped_l)?;
        transcript.commit_wrapped_affine(cs, wrapped_r)?;

        let c = transcript.get_challenge();
        challenges.push(c);
    }

    Ok(challenges)
}
