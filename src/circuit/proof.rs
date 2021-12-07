use franklin_crypto::bellman::pairing::ff::Field;
use franklin_crypto::bellman::pairing::CurveProjective;

use crate::circuit::transcript::Transcript;

pub struct IpaProof<G: CurveProjective> {
  pub l: Vec<G>,
  pub r: Vec<G>,
  pub a: G::Scalar,
}

impl<G: CurveProjective> IpaProof<G> {
  pub fn generate_challenges(&self, transcript: &mut Transcript) -> Vec<G::Scalar> {
    let mut challenges = vec![G::Scalar::zero(); self.l.len()];
    for (i, (l, r)) in self.l.iter().zip(&self.r).enumerate() {
      transcript.append_point(&l.into_affine(), "L");
      transcript.append_point(&r.into_affine(), "R");
      challenges[i] = transcript.challenge_scalar::<G::Scalar>("x");
    }

    challenges
  }
}
