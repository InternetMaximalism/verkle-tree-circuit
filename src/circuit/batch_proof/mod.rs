use franklin_crypto::bellman::{Circuit, ConstraintSystem, Field, SynthesisError};
use franklin_crypto::circuit::ecc::EdwardsPoint;
use franklin_crypto::circuit::num::AllocatedNum;
use franklin_crypto::jubjub::JubjubEngine;

use super::ipa::config::IpaConfig;
use super::ipa::proof::OptionIpaProof;
use super::ipa::transcript::{Transcript, WrappedTranscript};
use super::ipa::IpaCircuit;
use super::utils::read_point_le;

pub struct BatchProofCircuit<'a, E: JubjubEngine> {
  pub transcript_params: Option<E::Fr>,
  pub proof: OptionIpaProof<E>,
  pub d: Option<(E::Fr, E::Fr)>,
  pub commitments: Vec<Option<(E::Fr, E::Fr)>>,
  pub ys: Vec<Option<E::Fr>>,
  pub zs: Vec<Option<u8>>,
  pub ipa_conf: IpaConfig<E>,
  pub jubjub_params: &'a E::Params,
}

impl<'a, E: JubjubEngine> Circuit<E> for BatchProofCircuit<'a, E> {
  fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
    let mut transcript = WrappedTranscript::new(self.transcript_params);
    // transcript.DomainSep("multiproof");

    if self.commitments.len() != self.ys.len() {
      panic!(
        "number of commitments = {}, while number of output points = {}",
        self.commitments.len(),
        self.ys.len()
      );
    }
    if self.commitments.len() != self.zs.len() {
      panic!(
        "number of commitments = {}, while number of input points = {}",
        self.commitments.len(),
        self.zs.len()
      );
    }

    let num_queries = self.commitments.len();
    if num_queries == 0 {
      // XXX: does this need to be a panic?
      // XXX: this comment is also in CreateMultiProof
      panic!("cannot create a multiproof with no data");
    }

    for i in 0..num_queries {
      transcript.commit_field_element(cs, &self.commitments[i].map(|p| p.0))?; // commitments[i]_x
      transcript.commit_field_element(cs, &self.commitments[i].map(|p| p.1))?; // commitments[i]_y
      transcript.commit_field_element(
        cs,
        &self.zs[i].map(|v| {
          let reader = &mut std::io::Cursor::new(vec![v]);

          read_point_le::<E::Fr>(reader).unwrap()
        }),
      )?;
      transcript.commit_field_element(cs, &self.ys[i])?;
      // y
    }

    let challenge = transcript.get_challenge();
    let r: AllocatedNum<E> = AllocatedNum::alloc(cs.namespace(|| "alloc r"), || {
      challenge.ok_or(SynthesisError::Unsatisfiable)
    })?;

    transcript.commit_field_element(&mut cs.namespace(|| "commit"), &self.d.map(|v| v.0))?; // D_x
    transcript.commit_field_element(&mut cs.namespace(|| "commit"), &self.d.map(|v| v.1))?; // D_y
    let challenge = transcript.get_challenge();
    let t: AllocatedNum<E> = AllocatedNum::alloc(cs.namespace(|| "alloc t"), || {
      challenge.ok_or(SynthesisError::Unsatisfiable)
    })?;

    // Compute helper_scalars. This is r^i / t - z_i
    //
    // There are more optimal ways to do this, but
    // this is more readable, so will leave for now
    let mut minus_one = E::Fr::one();
    minus_one.negate(); // minus_one = -1
    let mut helper_scalars: Vec<AllocatedNum<E>> = Vec::with_capacity(num_queries);
    let mut powers_of_r = AllocatedNum::one::<CS>(); // powers_of_r = 1
    for i in 0..num_queries {
      // helper_scalars[i] = r^i / (t - z_i)
      let z_i: AllocatedNum<E> = AllocatedNum::alloc(cs.namespace(|| "alloc z"), || {
        self.zs[i]
          .map(|v| {
            let mut reader = std::io::Cursor::new(vec![v]);
            read_point_le::<E::Fr>(&mut reader).unwrap()
          })
          .ok_or(SynthesisError::Unsatisfiable)
      })?;
      let t_minus_z_i = t.sub(cs.namespace(|| "subtract z from helper_scalars_i"), &z_i)?;
      let inverse_of_t_minus_z_i =
        t_minus_z_i.pow(cs.namespace(|| "inverse helper_scalars_i"), &minus_one)?;
      let helper_scalars_i = inverse_of_t_minus_z_i.mul(
        cs.namespace(|| "multiply helper_scalars_i by powers_of_r"),
        &powers_of_r,
      )?;
      helper_scalars.push(helper_scalars_i);

      // powers_of_r *= r
      powers_of_r = powers_of_r.mul(cs.namespace(|| "multiply powers_of_r by r"), &r)?;
    }

    // Compute g_2(t) = SUM y_i * (r^i / t - z_i) = SUM y_i * helper_scalars
    let mut g_2_t: AllocatedNum<E> = AllocatedNum::zero(cs.namespace(|| "alloc zero"))?;
    for i in 0..num_queries {
      let mut tmp = AllocatedNum::alloc(cs.namespace(|| "alloc ys_i"), || Ok(self.ys[i].unwrap()))?;
      tmp = tmp.mul(
        cs.namespace(|| "multiply tmp by helper_scalars_i"),
        &helper_scalars[i],
      )?;
      g_2_t = g_2_t.add(cs.namespace(|| "add g_2_t to tmp"), &tmp)?;
    }

    // Compute E = SUM C_i * (r^i / t - z_i) = SUM C_i * helper_scalars
    let zero = AllocatedNum::zero(cs.namespace(|| "alloc zero"))?;
    let mut e = EdwardsPoint::interpret(
      cs.namespace(|| "interpret E"),
      &zero,
      &AllocatedNum::one::<CS>(),
      self.jubjub_params,
    )?;
    for i in 0..num_queries {
      let tmp_x = AllocatedNum::alloc(cs.namespace(|| "alloc tmp_x"), || {
        Ok(self.commitments[i].unwrap().0)
      })?;
      let tmp_y = AllocatedNum::alloc(cs.namespace(|| "alloc tmp_y"), || {
        Ok(self.commitments[i].unwrap().1)
      })?;
      let mut tmp = EdwardsPoint::interpret(
        cs.namespace(|| "interpret tmp"),
        &tmp_x,
        &tmp_y,
        self.jubjub_params,
      )?;
      let helper_scalars_i_bits =
        helper_scalars[i].into_bits_le(cs.namespace(|| "helper_scalars_i into LE bits"))?;
      tmp = tmp.mul(
        cs.namespace(|| "multiply tmp by helper_scalars_i_bits"),
        &helper_scalars_i_bits,
        self.jubjub_params,
      )?;
      e = e.add(cs.namespace(|| "add E to tmp"), &tmp, self.jubjub_params)?;
    }

    transcript.commit_field_element(cs, &e.get_x().get_value())?; // E_x
    transcript.commit_field_element(cs, &e.get_y().get_value())?; // E_y

    let minus_d_x = AllocatedNum::alloc(cs.namespace(|| "alloc -D_x"), || {
      let mut minus_d_x = self.d.unwrap().0;
      minus_d_x.negate();

      Ok(minus_d_x)
    })?;
    let d_y: AllocatedNum<E> =
      AllocatedNum::alloc(cs.namespace(|| "alloc D_y"), || Ok(self.d.unwrap().1))?;
    let minus_d = EdwardsPoint::interpret(
      cs.namespace(|| "interpret -D"),
      &minus_d_x,
      &d_y,
      self.jubjub_params,
    )?;
    let e_minus_d = e.add(
      cs.namespace(|| "subtract D from E"),
      &minus_d,
      self.jubjub_params,
    )?;

    let ipa_commitment = if let (Some(commitment_x), Some(commitment_y)) =
      (e_minus_d.get_x().get_value(), e_minus_d.get_y().get_value())
    {
      Some((commitment_x, commitment_y))
    } else {
      None
    };
    let transcript_params = transcript.get_challenge();
    let ipa = IpaCircuit::<'_, E> {
      commitment: ipa_commitment,
      proof: self.proof,
      eval_point: t.get_value(),
      inner_prod: g_2_t.get_value(),
      ipa_conf: self.ipa_conf,
      jubjub_params: self.jubjub_params,
      transcript_params,
    };

    ipa.synthesize(cs)
  }
}
