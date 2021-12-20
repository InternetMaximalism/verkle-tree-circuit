pub mod config;
pub mod proof;
pub mod utils;

use std::io::{Error, ErrorKind};

use franklin_crypto::bellman::pairing::{CurveAffine, CurveProjective, Engine};
use franklin_crypto::bellman::plonk::better_better_cs::cs::{
  Circuit, ConstraintSystem, Gate, GateInternal, Width4MainGateWithDNext,
};
use franklin_crypto::bellman::SynthesisError;
use franklin_crypto::plonk::circuit::allocated_num::AllocatedNum;
use franklin_crypto::plonk::circuit::bigint::field::RnsParameters;
use franklin_crypto::plonk::circuit::bigint::range_constraint_gate::TwoBitDecompositionRangecheckCustomGate;
use franklin_crypto::plonk::circuit::boolean::Boolean;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::aux_data::AuxData;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::WrappedAffinePoint;
use franklin_crypto::plonk::circuit::verifier_circuit::channel::ChannelGadget;
// use franklin_crypto::circuit::boolean::{AllocatedBit, Boolean};
// use franklin_crypto::circuit::num::AllocatedNum;

use crate::circuit::ipa::config::compute_barycentric_coefficients;

use self::config::IpaConfig;
use self::proof::{generate_challenges, OptionIpaProof};
use self::utils::{commit, fold_points, fold_scalars};

#[derive(Clone, Debug)]
pub struct IpaCircuit<
  'a,
  E: Engine,
  WP: WrappedAffinePoint<'a, E>,
  AD: AuxData<E>,
  T: ChannelGadget<E>,
> {
  pub commitment: Option<E::G1>,
  pub proof: OptionIpaProof<E::G1>,
  pub eval_point: Option<<E::G1 as CurveProjective>::Scalar>,
  pub inner_prod: Option<<E::G1 as CurveProjective>::Scalar>,
  pub ic: IpaConfig<E::G1>,
  pub rns_params: &'a RnsParameters<E, <E::G1Affine as CurveAffine>::Base>,
  pub aux_data: AD,
  pub transcript_params: &'a T::Params,
  pub _m: std::marker::PhantomData<WP>,
}

impl<'a, E: Engine, T: ChannelGadget<E>, WP: WrappedAffinePoint<'a, E>, AD: AuxData<E>> Circuit<E>
  for IpaCircuit<'a, E, WP, AD, T>
{
  type MainGate = Width4MainGateWithDNext;

  fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
    Ok(vec![
      Self::MainGate::default().into_internal(),
      TwoBitDecompositionRangecheckCustomGate::default().into_internal(),
    ])
  }

  fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
    let mut transcript = T::new(self.transcript_params);
    // transcript.consume("ipa", cs);

    println!("{:?}", self.proof);
    if self.proof.l.len() != self.proof.r.len() {
      return Err(Error::new(ErrorKind::InvalidData, "L and R should be the same size").into());
    }

    if self.proof.l.len() != self.ic.num_ipa_rounds {
      return Err(
        Error::new(
          ErrorKind::InvalidData,
          "The number of points for L or R should be equal to the number of rounds",
        )
        .into(),
      );
    }

    let eval_point = AllocatedNum::alloc(cs, || Ok(self.eval_point.unwrap()))?;
    let inner_prod = AllocatedNum::alloc(cs, || Ok(self.inner_prod.unwrap()))?;
    let mut commitment = WP::alloc(
      cs,
      self.commitment.map(|v| v.into_affine()),
      &self.rns_params,
      &self.aux_data,
    )?;

    let bit_limit = Some(256usize);
    let mut b =
      compute_barycentric_coefficients::<E, CS>(cs, &self.ic.precomputed_weights, eval_point)?;

    if b.len() != self.ic.srs.len() {
      return Err(
        Error::new(
          ErrorKind::InvalidData,
          "`barycentric_coefficients` had incorrect length",
        )
        .into(),
      );
    }

    transcript.consume_point(cs, commitment.clone())?; // C
    transcript.consume(eval_point.into(), cs)?; // input point
    transcript.consume(inner_prod.clone(), cs)?; // output point

    let w = transcript.produce_challenge(cs)?; // w

    let mut q = WP::alloc(
      cs,
      Some(self.ic.q.into_affine()),
      &self.rns_params,
      &self.aux_data,
    )?;
    let mut qy = q.clone();
    q = q.mul::<CS, AD>(cs, &w, bit_limit, &self.rns_params, &self.aux_data)?;

    qy = qy.mul::<CS, AD>(cs, &inner_prod, bit_limit, &self.rns_params, &self.aux_data)?;
    commitment = commitment.add::<CS>(cs, &mut qy.clone(), &self.rns_params)?;

    let challenges = generate_challenges::<E, CS, WP, AD, T>(
      cs,
      &self.proof.clone(),
      &mut transcript,
      &self.rns_params,
      &self.aux_data,
    )
    .unwrap();

    let mut challenges_inv: Vec<AllocatedNum<E>> = Vec::with_capacity(challenges.len());

    // Compute expected commitment
    for (i, &x) in challenges.iter().enumerate() {
      let l = WP::alloc(
        cs,
        self.proof.l[i].map(|l| l.into_affine()),
        &self.rns_params,
        &self.aux_data,
      )?;
      let r = WP::alloc(
        cs,
        self.proof.l[i].map(|r| r.into_affine()),
        &self.rns_params,
        &self.aux_data,
      )?;

      let x_inv = x.inverse::<CS>(cs).unwrap();
      challenges_inv.push(x_inv.clone());

      let one = AllocatedNum::one::<CS>(cs);
      commitment = commit::<E, CS, WP, AD>(
        cs,
        &[commitment, l, r],
        &[one, x, x_inv],
        bit_limit,
        &self.rns_params,
        &self.aux_data,
      )?;
    }

    let mut current_basis = self
      .ic
      .srs
      .iter()
      .map(|v| WP::alloc(cs, Some(v.into_affine()), &self.rns_params, &self.aux_data))
      .collect::<Result<Vec<_>, SynthesisError>>()?;

    for x_inv in challenges_inv {
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

      b = fold_scalars::<E, CS>(cs, &b_l, &b_r, x_inv.clone())?;
      current_basis = fold_points::<E, CS, WP, AD>(
        cs,
        &g_l,
        &g_r,
        x_inv.clone(),
        bit_limit,
        &self.rns_params,
        &self.aux_data,
      )?;
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
    let proof_a = AllocatedNum::alloc(cs, || Ok(self.proof.a.unwrap()))?;
    let mut result = current_basis[0].clone();
    result = result.mul::<CS, AD>(cs, &proof_a, bit_limit, &self.rns_params, &self.aux_data)?;

    let mut part_2a = b[0];

    part_2a = part_2a.mul::<CS>(cs, &proof_a)?;
    q = q.mul::<CS, AD>(cs, &part_2a, bit_limit, &self.rns_params, &self.aux_data)?;

    result = result.add::<CS>(cs, &mut q.clone(), &self.rns_params)?;

    // result == commitment
    let is_ok = result.equals::<CS>(cs, &commitment, &self.rns_params)?;
    Boolean::enforce_equal(cs, &is_ok, &Boolean::constant(true))?;

    Ok(())
  }
}
