pub mod config;
pub mod dummy_transcript;
pub mod proof;
pub mod transcript;
pub mod utils;

use std::io::{Error, ErrorKind};

use franklin_crypto::bellman::{Circuit, ConstraintSystem, Field, SynthesisError};
use franklin_crypto::circuit::ecc::EdwardsPoint;
use franklin_crypto::circuit::num::AllocatedNum;
use franklin_crypto::jubjub::JubjubEngine;
// use franklin_crypto::plonk::circuit::verifier_circuit::channel::ChannelGadget;

use crate::circuit::ipa::config::compute_barycentric_coefficients;

use self::config::IpaConfig;
use self::proof::{generate_challenges, OptionIpaProof};
use self::transcript::{Transcript, WrappedTranscript};
use self::utils::{commit, fold_points, fold_scalars};

#[derive(Clone)]
pub struct IpaCircuit<'a, E: JubjubEngine> {
  pub transcript_params: Option<E::Fr>,
  pub commitment: Option<(E::Fr, E::Fr)>,
  pub proof: OptionIpaProof<E>,
  pub eval_point: Option<E::Fr>,
  pub inner_prod: Option<E::Fr>,
  pub ipa_conf: IpaConfig<E>,
  pub jubjub_params: &'a E::Params,
}

impl<'a, E: JubjubEngine> Circuit<E> for IpaCircuit<'a, E> {
  fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
    let mut transcript = WrappedTranscript::new(self.transcript_params);
    // transcript.consume("ipa", cs);

    // println!("{:?}", self.proof);
    if self.proof.l.len() != self.proof.r.len() {
      return Err(Error::new(ErrorKind::InvalidData, "L and R should be the same size").into());
    }

    if self.proof.l.len() != self.ipa_conf.num_ipa_rounds {
      return Err(
        Error::new(
          ErrorKind::InvalidData,
          "The number of points for L or R should be equal to the number of rounds",
        )
        .into(),
      );
    }

    let eval_point = AllocatedNum::alloc(cs.namespace(|| "alloc eval_point"), || {
      Ok(self.eval_point.unwrap())
    })?;
    let inner_prod = AllocatedNum::alloc(cs.namespace(|| "alloc inner_prod"), || {
      Ok(self.inner_prod.unwrap())
    })?;
    // let wrapped_base_point = EdwardsPoint::interpret(
    //   cs.namespace(|| "base_point"),
    //   &wrapped_base_point_x,
    //   &wrapped_base_point_y,
    //   &self.jubjub_params,
    // )?;
    let commitment_x = AllocatedNum::alloc(cs.namespace(|| "alloc commitment_x"), || {
      Ok(self.commitment.unwrap().0)
    })?;
    let commitment_y = AllocatedNum::alloc(cs.namespace(|| "alloc commitment_y"), || {
      Ok(self.commitment.unwrap().1)
    })?;
    let mut commitment = EdwardsPoint::interpret(
      cs.namespace(|| "interpret commitment"),
      &commitment_x,
      &commitment_y,
      &self.jubjub_params,
    )?;

    // let bit_limit = None; // Some(256usize);
    let mut b = compute_barycentric_coefficients(
      &mut cs.namespace(|| "compute_barycentric_coefficients"),
      &self.ipa_conf.precomputed_weights,
      &eval_point,
    )?;

    if b.len() != self.ipa_conf.srs.len() {
      return Err(
        Error::new(
          ErrorKind::InvalidData,
          "`barycentric_coefficients` had incorrect length",
        )
        .into(),
      );
    }

    transcript.commit_field_element(cs, &commitment.get_x().get_value())?;
    transcript.commit_field_element(cs, &commitment.get_y().get_value())?;
    transcript.commit_field_element(cs, &eval_point.get_value())?;
    transcript.commit_field_element(cs, &inner_prod.get_value())?;
    // transcript.commit_field_element(&commitment.get_x().get_value().unwrap()); // C_x
    // transcript.commit_field_element(&commitment.get_y().get_value().unwrap()); // C_y
    // transcript.commit_field_element(&eval_point.get_value().unwrap()); // input point
    // transcript.commit_field_element(&inner_prod.get_value().unwrap()); // output point

    let challenge = transcript.get_challenge();
    let w: AllocatedNum<E> = AllocatedNum::alloc(cs.namespace(|| "alloc w"), || {
      challenge.ok_or(SynthesisError::Unsatisfiable)
    })?;

    let q_x = AllocatedNum::alloc(cs.namespace(|| "alloc Q_x"), || Ok(self.ipa_conf.q.0))?;
    let q_y = AllocatedNum::alloc(cs.namespace(|| "alloc Q_y"), || Ok(self.ipa_conf.q.1))?;
    let mut q = EdwardsPoint::interpret(
      cs.namespace(|| "interpret Q"),
      &q_x,
      &q_y,
      &self.jubjub_params,
    )?;
    let mut qy = q.clone();
    let w_bits = w.into_bits_le(cs.namespace(|| "into_bits_le"))?;
    q = q.mul(cs.namespace(|| "q_mul_w"), &w_bits, &self.jubjub_params)?;

    let inner_prod_bits = inner_prod.into_bits_le(&mut cs.namespace(|| "into_bits_le"))?;
    qy = qy.mul(
      cs.namespace(|| "qy_mul_inner_prod"),
      &inner_prod_bits,
      &self.jubjub_params,
    )?;
    commitment = commitment.add(
      cs.namespace(|| "add qy to commitment"),
      &mut qy.clone(),
      &self.jubjub_params,
    )?;

    let challenges = generate_challenges(
      &mut cs.namespace(|| "generate_challenges"),
      &self.proof.clone(),
      &mut transcript,
    )
    .unwrap();

    let mut challenges_inv: Vec<AllocatedNum<E>> = Vec::with_capacity(challenges.len());

    // Compute expected commitment
    for (i, x) in challenges.iter().enumerate() {
      println!("challenges_inv: {}/{}", i, challenges.len());
      let l_i_x = AllocatedNum::alloc(cs.namespace(|| "alloc l_i_x"), || {
        Ok(self.proof.l[i].unwrap().0)
        // self.proof.l[i]
        //   .map(|v| v.0)
        //   .ok_or(SynthesisError::UnconstrainedVariable)
      })?;
      let l_i_y = AllocatedNum::alloc(cs.namespace(|| "alloc l_i_y"), || {
        Ok(self.proof.l[i].unwrap().1)
        // self.proof.l[i]
        //   .map(|v| v.1)
        //   .ok_or(SynthesisError::UnconstrainedVariable)
      })?;
      let l: EdwardsPoint<E> = EdwardsPoint::interpret(
        cs.namespace(|| "interpret l"),
        &l_i_x,
        &l_i_y,
        &self.jubjub_params,
      )?;
      let r_i_x = AllocatedNum::alloc(cs.namespace(|| "alloc r_i_x"), || {
        Ok(self.proof.r[i].unwrap().0)
        // self.proof.r[i]
        //   .map(|v| v.0)
        //   .ok_or(SynthesisError::UnconstrainedVariable)
      })?;
      let r_i_y = AllocatedNum::alloc(cs.namespace(|| "alloc r_i_x"), || {
        Ok(self.proof.r[i].unwrap().1)
        // self.proof.r[i]
        //   .map(|v| v.1)
        //   .ok_or(SynthesisError::UnconstrainedVariable)
      })?;
      let r: EdwardsPoint<E> = EdwardsPoint::interpret(
        cs.namespace(|| "interpret r"),
        &r_i_x,
        &r_i_y,
        &self.jubjub_params,
      )?;

      let mut minus_one = E::Fr::one();
      minus_one.negate();
      let x_inv = x.pow(cs.namespace(|| "inverse x"), &minus_one).unwrap();
      challenges_inv.push(x_inv.clone());

      let one = AllocatedNum::one::<CS>();
      commitment = commit(
        &mut cs.namespace(|| "commit"),
        &[commitment, l, r],
        &[one, x.clone(), x_inv],
        &self.jubjub_params,
      )?;
    }

    println!("challenges_inv: {}/{}", challenges.len(), challenges.len());

    let mut current_basis = self
      .ipa_conf
      .srs
      .iter()
      .map(|v| {
        let v_x = AllocatedNum::alloc(cs.namespace(|| "alloc v_x"), || Ok(v.0))?;
        let v_y = AllocatedNum::alloc(cs.namespace(|| "alloc v_y"), || Ok(v.1))?;
        EdwardsPoint::interpret(
          cs.namespace(|| "interpret v"),
          &v_x,
          &v_y,
          &self.jubjub_params,
        )
      })
      .collect::<Result<Vec<_>, SynthesisError>>()?;

    println!("reduction starts");
    let start = std::time::Instant::now();

    for (i, x_inv) in challenges_inv.iter().enumerate() {
      println!("x_inv: {}/{}", i, challenges_inv.len());
      assert_eq!(
        current_basis.len() % 2,
        0,
        "cannot split `current_basis` in half"
      );
      let mut g_chunks = current_basis.chunks(current_basis.len() / 2);
      let g_l = g_chunks.next().unwrap().to_vec();
      let g_r = g_chunks.next().unwrap().to_vec();

      let mut b_chunks = b.chunks(b.len() / 2);
      let b_l = b_chunks.next().unwrap().to_vec();
      let b_r = b_chunks.next().unwrap().to_vec();

      b = fold_scalars::<E, CS>(cs, &b_l, &b_r, x_inv)?;
      current_basis = fold_points::<E, CS>(cs, &g_l, &g_r, x_inv, &self.jubjub_params)?;
    }

    println!("x_inv: {}/{}", challenges_inv.len(), challenges_inv.len());

    if b.len() != 1 {
      return Err(
        Error::new(
          ErrorKind::InvalidData,
          "`b` and `current_basis` should be 1",
        )
        .into(),
      );
    }

    println!(
      "reduction ends: {} s",
      start.elapsed().as_millis() as f64 / 1000.0
    );

    println!("verification check starts");
    let start = std::time::Instant::now();

    // Compute `result = G[0] * a + (a * b[0]) * Q`.
    let proof_a = AllocatedNum::alloc(cs.namespace(|| "alloc proof_a"), || {
      Ok(self.proof.a.unwrap())
    })?;
    let mut result1 = current_basis[0].clone(); // result1 = G[0]
    let mut part_2a = b[0].clone(); // part_2a = b[0]

    let proof_a_bits = proof_a.into_bits_le(cs.namespace(|| "alloc proof_a"))?;
    result1 = result1.mul(
      cs.namespace(|| "alloc proof_a"),
      &proof_a_bits,
      &self.jubjub_params,
    )?; // result1 *= proof_a

    part_2a = part_2a.mul(cs.namespace(|| "multiply part_2a by proof_a"), &proof_a)?; // part_2a *= proof_a
    let part_2a_bits = part_2a.into_bits_le(cs.namespace(|| "part_2a into LE bits"))?;
    let result2 = q.mul(
      cs.namespace(|| "multiply q by part_2a_bits"),
      &part_2a_bits,
      &self.jubjub_params,
    )?; // q *= part_2a

    let result = result1.add(
      cs.namespace(|| "add result1 to result2"),
      &result2,
      &self.jubjub_params,
    )?; // result = result1 + result2

    // Ensure `commitment` is equal to `result`.
    AllocatedNum::equals(
      cs.namespace(|| "ensure commitment_x is equal to result_y"),
      &commitment.get_x(),
      &result.get_x(),
    )?;
    AllocatedNum::equals(
      cs.namespace(|| "ensure commitment_y is equal to result_y"),
      &commitment.get_y(),
      &result.get_y(),
    )?;

    println!(
      "verification check ends: {} s",
      start.elapsed().as_millis() as f64 / 1000.0
    );

    Ok(())
  }
}
