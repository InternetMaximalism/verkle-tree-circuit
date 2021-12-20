use franklin_crypto::bellman::pairing::{CurveAffine, CurveProjective, Engine};
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use franklin_crypto::bellman::SynthesisError;
use franklin_crypto::plonk::circuit::allocated_num::AllocatedNum;
use franklin_crypto::plonk::circuit::bigint::field::RnsParameters;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::aux_data::AuxData;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::WrappedAffinePoint;
use franklin_crypto::plonk::circuit::verifier_circuit::channel::ChannelGadget;

// use super::transcript::Transcript;

#[derive(Clone, Debug)]
pub struct IpaProof<G: CurveProjective> {
  pub l: Vec<G>,
  pub r: Vec<G>,
  pub a: G::Scalar,
}

#[derive(Clone, Debug)]
pub struct OptionIpaProof<G: CurveProjective> {
  pub l: Vec<Option<G>>,
  pub r: Vec<Option<G>>,
  pub a: Option<G::Scalar>,
}

impl<G: CurveProjective> OptionIpaProof<G> {
  pub fn with_depth(depth: usize) -> Self {
    Self {
      l: vec![None; depth],
      r: vec![None; depth],
      a: None,
    }
  }
}

impl<G: CurveProjective> From<IpaProof<G>> for OptionIpaProof<G> {
  fn from(ipa_proof: IpaProof<G>) -> Self {
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
  T: ChannelGadget<E>,
>(
  cs: &mut CS,
  ipa_proof: &OptionIpaProof<E::G1>,
  transcript: &mut T,
  rns_params: &'a RnsParameters<E, <E::G1Affine as CurveAffine>::Base>,
  aux_data: &AD,
) -> Result<Vec<AllocatedNum<E>>, SynthesisError> {
  let mut challenges: Vec<AllocatedNum<E>> = Vec::with_capacity(ipa_proof.l.len());
  for (ls, rs) in ipa_proof.l.iter().zip(&ipa_proof.r) {
    let wrapped_l = WP::alloc::<CS, AD>(cs, ls.map(|l| l.into_affine()), rns_params, aux_data)?;
    let wrapped_r = WP::alloc::<CS, AD>(cs, rs.map(|r| r.into_affine()), rns_params, aux_data)?;
    transcript.consume_point(cs, wrapped_l)?; // L
    transcript.consume_point(cs, wrapped_r)?; // R
    challenges.push(transcript.produce_challenge(cs)?); // x
  }

  Ok(challenges)
}
