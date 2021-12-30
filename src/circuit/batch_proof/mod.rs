use franklin_crypto::bellman::plonk::commitments::transcript::Transcript;
use franklin_crypto::bellman::{Circuit, ConstraintSystem, Field, SynthesisError};
use franklin_crypto::circuit::ecc::EdwardsPoint;
use franklin_crypto::circuit::num::AllocatedNum;
use franklin_crypto::jubjub::JubjubEngine;

use super::ipa::config::IpaConfig;
use super::ipa::proof::OptionIpaProof;
use super::ipa::IpaCircuit;
use super::utils::read_point;

pub struct BatchProofCircuit<'a, E: JubjubEngine, T: Transcript<E::Fr>> {
  pub proof: OptionIpaProof<E>,
  pub d: Option<(E::Fr, E::Fr)>,
  pub commitments: Vec<Option<(E::Fr, E::Fr)>>,
  pub ys: Vec<Option<E::Fr>>,
  pub zs: Vec<Option<u8>>,
  pub ipa_conf: IpaConfig<E>,
  pub jubjub_params: &'a E::Params,
  pub _transcript_params: std::marker::PhantomData<T>,
}

impl<'a, E: JubjubEngine, T: Transcript<E::Fr>> Circuit<E> for BatchProofCircuit<'a, E, T> {
  fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
    let mut transcript = T::new();
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
      self.commitments[i].map(|p| transcript.commit_field_element(&p.0)); // commitments[i]_x
      self.commitments[i].map(|p| transcript.commit_field_element(&p.1)); // commitments[i]_y
      self.zs[i].map(|v| transcript.commit_bytes(&[v]));
      self.ys[i].map(|v| transcript.commit_field_element(&v)); // y
    }
    // TODO: Add hash constraints or check hash validity.
    let challenge = transcript.get_challenge_bytes();
    let mut reader = std::io::Cursor::new(challenge);
    let r: AllocatedNum<E> = AllocatedNum::alloc(cs.namespace(|| "alloc r"), || {
      Ok(read_point::<E::Fr>(&mut reader).unwrap())
    })?; // r

    self.d.map(|v| transcript.commit_field_element(&v.0)); // D_x
    self.d.map(|v| transcript.commit_field_element(&v.1)); // D_y
    let challenge = transcript.get_challenge_bytes();
    let mut reader = std::io::Cursor::new(challenge);
    let t: AllocatedNum<E> = AllocatedNum::alloc(cs.namespace(|| "alloc t"), || {
      Ok(read_point::<E::Fr>(&mut reader).unwrap())
    })?; // t

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
            read_point::<E::Fr>(&mut reader).unwrap()
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
      cs.namespace(|| "interpret"),
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
        helper_scalars[i].into_bits_le(cs.namespace(|| "helper_scalars_i into_bits_le"))?;
      tmp = tmp.mul(
        cs.namespace(|| "multiply tmp by helper_scalars_i_bits"),
        &helper_scalars_i_bits,
        self.jubjub_params,
      )?;
      e = e.add(cs.namespace(|| "add e to tmp"), &tmp, self.jubjub_params)?;
    }

    e.get_x()
      .get_value()
      .map(|v| transcript.commit_field_element(&v)); // E_x
    e.get_y()
      .get_value()
      .map(|v| transcript.commit_field_element(&v)); // E_y

    let minus_d_x = AllocatedNum::alloc(cs.namespace(|| "alloc tmp_x"), || {
      let mut minus_d_x = self.d.unwrap().0;
      minus_d_x.negate();

      Ok(minus_d_x)
    })?;
    let d_y: AllocatedNum<E> =
      AllocatedNum::alloc(cs.namespace(|| "alloc tmp_y"), || Ok(self.d.unwrap().1))?;
    let minus_d =
      EdwardsPoint::interpret(cs.namespace(|| ""), &minus_d_x, &d_y, self.jubjub_params)?;
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
    let ipa = IpaCircuit::<'_, E, T> {
      commitment: ipa_commitment,
      proof: self.proof,
      eval_point: t.get_value(),
      inner_prod: g_2_t.get_value(),
      ipa_conf: self.ipa_conf,
      jubjub_params: self.jubjub_params,
      _transcript_params: std::marker::PhantomData,
    };

    ipa.synthesize(&mut cs.namespace(|| "IPA"))
  }
}
