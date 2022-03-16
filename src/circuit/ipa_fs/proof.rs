use franklin_crypto::babyjubjub::{edwards, JubjubEngine, Unknown};
use franklin_crypto::bellman::{ConstraintSystem, SynthesisError};
use franklin_crypto::circuit::baby_ecc::EdwardsPoint;
use franklin_crypto::circuit::num::AllocatedNum;
use verkle_tree::ipa_fs::proof::IpaProof;

use super::transcript::Transcript;

#[derive(Clone)]
pub struct OptionIpaProof<E: JubjubEngine> {
    pub l: Vec<Option<edwards::Point<E, Unknown>>>,
    pub r: Vec<Option<edwards::Point<E, Unknown>>>,
    pub a: Option<E::Fs>,
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

#[derive(Clone)]
pub struct WrappedIpaProof<E: JubjubEngine> {
    pub l: Vec<EdwardsPoint<E>>,
    pub r: Vec<EdwardsPoint<E>>,
    pub a: Option<E::Fs>,
}

impl<E: JubjubEngine> From<IpaProof<E>> for OptionIpaProof<E> {
    fn from(ipa_proof: IpaProof<E>) -> Self {
        Self {
            l: ipa_proof
                .l
                .iter()
                .map(|l| Some(l.clone()))
                .collect::<Vec<_>>(),
            r: ipa_proof
                .r
                .iter()
                .map(|r| Some(r.clone()))
                .collect::<Vec<_>>(),
            a: Some(ipa_proof.a),
        }
    }
}

pub fn generate_challenges<'a, 'b, E, CS, T>(
    cs: &mut CS,
    ipa_proof: &OptionIpaProof<E>,
    transcript: &mut T,
    jubjub_params: &E::Params,
) -> Result<(Vec<Option<E::Fs>>, WrappedIpaProof<E>), SynthesisError>
where
    'b: 'a,
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
    T: Transcript<E>,
{
    let mut challenges = Vec::with_capacity(ipa_proof.l.len());
    let mut wrapped_proof_l = Vec::with_capacity(ipa_proof.l.len());
    let mut wrapped_proof_r = Vec::with_capacity(ipa_proof.r.len());
    for (l, r) in ipa_proof.l.iter().zip(&ipa_proof.r) {
        let raw_l = if let Some(l) = l {
            let (x, y) = l.into_xy();
            (Some(x), Some(y))
        } else {
            (None, None)
        };
        let l_x = AllocatedNum::alloc(cs.namespace(|| "allocate L_x"), || {
            raw_l.0.ok_or(SynthesisError::UnconstrainedVariable)
        })?;
        let l_y = AllocatedNum::alloc(cs.namespace(|| "allocate L_y"), || {
            raw_l.1.ok_or(SynthesisError::UnconstrainedVariable)
        })?;
        let wrapped_l =
            EdwardsPoint::interpret(cs.namespace(|| "allocate L"), &l_x, &l_y, jubjub_params)?;
        transcript.commit_point(cs, &wrapped_l)?; // L

        let raw_r = if let Some(r) = r {
            let (x, y) = r.into_xy();
            (Some(x), Some(y))
        } else {
            (None, None)
        };
        let r_x = AllocatedNum::alloc(cs.namespace(|| "allocate R_x"), || {
            raw_r.0.ok_or(SynthesisError::UnconstrainedVariable)
        })?;
        let r_y = AllocatedNum::alloc(cs.namespace(|| "allocate R_y"), || {
            raw_r.1.ok_or(SynthesisError::UnconstrainedVariable)
        })?;
        let wrapped_r =
            EdwardsPoint::interpret(cs.namespace(|| "allocate R"), &r_x, &r_y, jubjub_params)?;
        transcript.commit_point(cs, &wrapped_r)?; // R

        let c = transcript.get_challenge(cs)?;
        challenges.push(c);
        wrapped_proof_l.push(wrapped_l);
        wrapped_proof_r.push(wrapped_r);
    }

    Ok((
        challenges,
        WrappedIpaProof {
            l: wrapped_proof_l,
            r: wrapped_proof_r,
            a: ipa_proof.a,
        },
    ))
}
