use franklin_crypto::babyjubjub::{edwards, JubjubEngine, Unknown};
use franklin_crypto::bellman::plonk::better_better_cs::cs::{
    Circuit, ConstraintSystem, Gate, GateInternal, Width4MainGateWithDNext,
};
use franklin_crypto::bellman::PrimeFieldRepr;
use franklin_crypto::bellman::{Field, PrimeField, SynthesisError};
use franklin_crypto::plonk::circuit::allocated_num::AllocatedNum;
use franklin_crypto::plonk::circuit::bigint::field::{FieldElement, RnsParameters};
use franklin_crypto::plonk::circuit::bigint::range_constraint_gate::TwoBitDecompositionRangecheckCustomGate;
use verkle_tree::ipa_fs::config::IpaConfig;

use crate::circuit::ipa_fs::utils::convert_bits_le;
use crate::circuit::num::baby_ecc::EdwardsPoint;

use super::ipa_fs::circuit::IpaCircuit;
use super::ipa_fs::proof::OptionIpaProof;
use super::ipa_fs::transcript::{Transcript, WrappedTranscript};

pub struct BatchProofCircuit<'a, 'b, 'c, E: JubjubEngine>
where
    'c: 'b,
{
    pub transcript_params: Option<E::Fr>,
    pub proof: OptionIpaProof<E>,
    pub d: Option<edwards::Point<E, Unknown>>,
    pub commitments: Vec<Option<edwards::Point<E, Unknown>>>,
    pub ys: Vec<Option<E::Fs>>,
    pub zs: Vec<Option<usize>>,
    pub ipa_conf: &'c IpaConfig<'b, E>,
    pub rns_params: &'a RnsParameters<E, E::Fs>,
    pub jubjub_params: &'a E::Params,
}

impl<'a, 'b, 'c, E: JubjubEngine> Circuit<E> for BatchProofCircuit<'a, 'b, 'c, E> {
    type MainGate = Width4MainGateWithDNext;

    fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
        Ok(vec![
            Self::MainGate::default().into_internal(),
            TwoBitDecompositionRangecheckCustomGate::default().into_internal(),
        ])
    }

    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        let transcript_params = self.transcript_params;
        dbg!(transcript_params);
        let wrapped_transcript_params = AllocatedNum::<E>::alloc(cs, || {
            transcript_params.ok_or(SynthesisError::UnconstrainedVariable)
        })?;
        let mut transcript = WrappedTranscript::new(cs, wrapped_transcript_params);

        let ys = self
            .ys
            .iter()
            .map(|&yi| FieldElement::new_allocated_in_field(cs, yi, self.rns_params))
            .collect::<Result<Vec<_>, SynthesisError>>()?;
        let zs = self
            .zs
            .iter()
            .map(|&zi| {
                FieldElement::new_allocated_in_field(
                    cs,
                    zi.map(|zi| {
                        E::Fs::from_repr(<E::Fs as PrimeField>::Repr::from(zi as u64)).unwrap()
                    }),
                    self.rns_params,
                )
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        dbg!(self
            .commitments
            .iter()
            .map(|v| v.as_ref().map(|v| v.into_xy()))
            .collect::<Vec<_>>());
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
            panic!("cannot create a multi proof with no data");
        }

        let mut allocated_commitment = vec![];
        for i in 0..num_queries {
            let allocated_commitment_i = {
                let raw_commitment = if let Some(c) = self.commitments[i].clone() {
                    let (x, y) = c.into_xy();
                    (Some(x), Some(y))
                } else {
                    (None, None)
                };
                let commitment_x = AllocatedNum::alloc(cs, || {
                    raw_commitment
                        .0
                        .ok_or(SynthesisError::UnconstrainedVariable)
                })?;
                let commitment_y = AllocatedNum::alloc(cs, || {
                    raw_commitment
                        .1
                        .ok_or(SynthesisError::UnconstrainedVariable)
                })?;

                EdwardsPoint::interpret(cs, &commitment_x, &commitment_y, self.jubjub_params)?
            };

            transcript.commit_point(cs, &allocated_commitment_i)?; // commitments[i]
            allocated_commitment.push(allocated_commitment_i);
            // let zi = self.zs[i]
            //     .map(|zi| E::Fs::from_repr(<E::Fs as PrimeField>::Repr::from(zi as u64)).unwrap());
            transcript.commit_field_element(cs, &zs[i])?; // z
            transcript.commit_field_element(cs, &ys[i])?; // y
        }

        let r = transcript.get_challenge(cs, self.rns_params)?;

        let allocated_d = {
            let raw_commitment = if let Some(d) = self.d.clone() {
                let (x, y) = d.into_xy();
                (Some(x), Some(y))
            } else {
                (None, None)
            };
            let commitment_x = AllocatedNum::alloc(cs, || {
                raw_commitment
                    .0
                    .ok_or(SynthesisError::UnconstrainedVariable)
            })?;
            let commitment_y = AllocatedNum::alloc(cs, || {
                raw_commitment
                    .1
                    .ok_or(SynthesisError::UnconstrainedVariable)
            })?;

            EdwardsPoint::interpret(cs, &commitment_x, &commitment_y, self.jubjub_params)?
        };
        transcript.commit_point(cs, &allocated_d)?; // D
        let t = transcript.get_challenge(cs, self.rns_params)?;

        // Compute helper_scalars. This is r^i / t - z_i
        //
        // There are more optimal ways to do this, but
        // this is more readable, so will leave for now
        let mut helper_scalars = Vec::with_capacity(num_queries);
        let mut powers_of_r = FieldElement::new_constant(E::Fs::one(), self.rns_params); // powers_of_r = 1
        for zi in zs {
            // helper_scalars[i] = r^i / (t - z_i)
            // let zi = E::Fs::from_repr(<E::Fs as PrimeField>::Repr::from(zi as u64)).unwrap();
            // let mut t_minus_zi = t;
            let (t_minus_zi, _) = t.clone().sub(cs, zi.clone())?;
            let raw_inv_t_minus_zi = if let Some(raw_t_minus_zi) = t_minus_zi.get_field_value() {
                raw_t_minus_zi.inverse()
            } else {
                None
            };
            let inv_t_minus_zi =
                FieldElement::new_allocated_in_field(cs, raw_inv_t_minus_zi, self.rns_params)?;

            let (tmp, _) = inv_t_minus_zi.mul(cs, powers_of_r.clone())?;
            helper_scalars.push(tmp);

            // powers_of_r *= r
            {
                let (tmp, _) = powers_of_r.clone().mul(cs, r.clone())?;
                powers_of_r = tmp;
            }
        }

        // Compute g_2(t) = SUM y_i * (r^i / t - z_i) = SUM y_i * helper_scalars
        let mut g_2_t = FieldElement::new_constant(E::Fs::zero(), self.rns_params);
        for (i, helper_scalars_i) in helper_scalars.iter().enumerate() {
            let (tmp, _) = ys[i].clone().mul(cs, helper_scalars_i.clone())?;
            let (tmp, _) = g_2_t.clone().add(cs, tmp)?;
            g_2_t = tmp;
        }

        // Compute E = SUM C_i * (r^i / t - z_i) = SUM C_i * helper_scalars
        assert!(!self.commitments.is_empty(), "`e` must be non-zero.");
        let mut e = {
            let helper_scalars_i_bits = convert_bits_le(cs, helper_scalars[0].clone(), None)?;
            allocated_commitment[0].mul(cs, &helper_scalars_i_bits, self.jubjub_params)?
        };
        for (i, helper_scalars_i) in helper_scalars.iter().enumerate().skip(1) {
            let helper_scalars_i_bits = convert_bits_le(cs, helper_scalars_i.clone(), None)?;
            let tmp =
                allocated_commitment[i].mul(cs, &helper_scalars_i_bits, self.jubjub_params)?;
            e = e.add(cs, &tmp, self.jubjub_params)?;
        }

        transcript.commit_point(cs, &e)?; // E

        let minus_d = {
            let (minus_d_x, d_y) = if let Some(d) = self.d.clone() {
                let (mut d_x, d_y) = d.into_xy();
                d_x.negate();

                (Some(d_x), Some(d_y))
            } else {
                (None, None)
            };
            let minus_d_x = AllocatedNum::alloc(cs, || {
                minus_d_x.ok_or(SynthesisError::UnconstrainedVariable)
            })?;
            let d_y = AllocatedNum::alloc(cs, || d_y.ok_or(SynthesisError::UnconstrainedVariable))?;

            EdwardsPoint::interpret(cs, &minus_d_x, &d_y, self.jubjub_params)?
        };
        let e_minus_d = e.add(cs, &minus_d, self.jubjub_params)?;
        let ipa_commitment = if let (Some(x), Some(y)) =
            (e_minus_d.get_x().get_value(), e_minus_d.get_y().get_value())
        {
            edwards::Point::get_for_y(y, x.into_repr().is_odd(), self.jubjub_params)
        } else {
            None
        };

        let transcript_params = transcript.into_params().get_value();
        let ipa = IpaCircuit::<E> {
            commitment: ipa_commitment,
            proof: self.proof.clone(),
            eval_point: t.get_field_value(),
            inner_prod: g_2_t.get_field_value(),
            ipa_conf: self.ipa_conf,
            jubjub_params: self.jubjub_params,
            rns_params: self.rns_params,
            transcript_params,
        };

        ipa.synthesize(cs)
    }
}
