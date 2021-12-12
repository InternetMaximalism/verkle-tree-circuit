pub mod config;
pub mod proof;
pub mod transcript;
pub mod utils;

use std::io::{Error, ErrorKind};

use franklin_crypto::bellman::pairing::ff::Field;
use franklin_crypto::bellman::pairing::{CurveProjective, Engine};
use franklin_crypto::bellman::{Circuit, ConstraintSystem, SynthesisError};
// use franklin_crypto::circuit::boolean::{AllocatedBit, Boolean};
// use franklin_crypto::circuit::num::AllocatedNum;

use self::config::IpaConfig;
use self::proof::IpaProof;
use self::transcript::Transcript;
use self::utils::{commit, fold_points, fold_scalars};

pub struct IpaCircuit<E: Engine> {
  pub transcript: Transcript,
  pub ic: IpaConfig<E::G1>,
  pub commitment: Option<E::G1>,
  pub proof: Option<IpaProof<E::G1>>,
  pub eval_point: Option<<E::G1 as CurveProjective>::Scalar>,
  pub inner_prod: Option<<E::G1 as CurveProjective>::Scalar>,
}

impl<E: Engine> Circuit<E> for IpaCircuit<E> {
  fn synthesize<CS: ConstraintSystem<E>>(self, _cs: &mut CS) -> Result<(), SynthesisError> {
    let mut transcript = self.transcript; // TODO: should mutate self.transcript
    transcript.domain_sep("ipa");

    let proof = self.proof.unwrap();
    if proof.l.len() == proof.r.len() {
      return Err(Error::new(ErrorKind::InvalidData, "L and R should be the same size").into());
    }

    if proof.l.len() == self.ic.num_ipa_rounds {
      return Err(
        Error::new(
          ErrorKind::InvalidData,
          "The number of points for L or R should be equal to the number of rounds",
        )
        .into(),
      );
    }

    let eval_point = self.eval_point.unwrap();
    let inner_prod = self.inner_prod.unwrap();
    let mut commitment = self.commitment.unwrap();

    let mut b = self
      .ic
      .precomputed_weights
      .compute_barycentric_coefficients(eval_point);

    transcript.append_point(&commitment.into_affine(), "C");
    transcript.append_scalar(&eval_point, "input point");
    transcript.append_scalar(&inner_prod, "output point");

    let w = transcript.challenge_scalar::<E::Fr>("w");

    let mut q = self.ic.q.clone();
    q.mul_assign(w);

    let mut qy = self.ic.q.clone();
    qy.mul_assign(inner_prod);
    commitment.add_assign(&qy);

    let challenges: Vec<E::Fr> = proof.generate_challenges(&mut transcript);
    let mut challenges_inv = vec![E::Fr::zero(); challenges.len()];

    // Compute expected commitment
    for (i, &x) in challenges.iter().enumerate() {
      let l = proof.l[i];
      let r = proof.r[i];

      let x_inv = x.inverse().unwrap();
      challenges_inv[i] = x_inv;

      commitment = commit::<E::G1>(&[commitment, l, r], &[E::Fr::one(), x, x_inv])?;
    }

    let mut current_basis = self.ic.srs;

    for x_inv in challenges_inv {
      let mut g_chunks = current_basis.chunks(current_basis.len() / 2);
      let g_l = g_chunks.next().unwrap().to_vec();
      let g_r = g_chunks.next().unwrap().to_vec();

      let mut b_chunks = b.chunks(b.len() / 2);
      let b_l = b_chunks.next().unwrap().to_vec();
      let b_r = b_chunks.next().unwrap().to_vec();

      b = fold_scalars(&b_l, &b_r, x_inv.clone())?;
      current_basis = fold_points(&g_l, &g_r, x_inv.clone())?;
    }

    if b.len() != current_basis.len() {
      return Err(Error::new(ErrorKind::InvalidData, "reduction was not correct").into());
    }

    if b.len() != 1 {
      return Err(
        Error::new(
          ErrorKind::InvalidData,
          "`b` and `current_basis` should be 1",
        )
        .into(),
      );
    }

    // C is equal to G[0] * a + (a * b[0]) * Q;
    let mut result = current_basis[0];
    result.mul_assign(proof.a);

    let mut part_2a = b[0];

    part_2a.mul_assign(&proof.a);
    q.mul_assign(part_2a);

    result.add_assign(&q);
    result.sub_assign(&commitment);
    assert!(result.is_zero(), "verification failed");

    // // Convert `output` to `output_fr`.
    // let one = AllocatedNum::<E>::alloc(cs.namespace(|| "one"), || Ok(E::Fr::one()))?;
    // let zero = AllocatedNum::<E>::alloc(cs.namespace(|| "zero"), || Ok(E::Fr::zero()))?;
    // let output_fr = AllocatedNum::conditionally_select(
    //   cs.namespace(|| "output_fr"),
    //   &one,
    //   &zero,
    //   &Boolean::from(output),
    // )?;

    // // `output` is a public variable, while `inputs[0]` and `inputs[1]` are private variables.
    // output_fr.inputize(cs.namespace(|| "public output"))?;

    Ok(())
  }
}

impl<E: Engine> IpaCircuit<E> {
  pub fn get_public_wires(&self) -> anyhow::Result<Vec<u8>> {
    let output = E::Fr::zero();

    let mut public_wires = hex::decode(output.to_string()[5..69].to_string())?;
    public_wires.reverse();

    Ok(public_wires)
  }
}
