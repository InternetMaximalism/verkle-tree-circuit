use franklin_crypto::babyjubjub::{edwards, JubjubEngine, Unknown};
use franklin_crypto::bellman::{Circuit, ConstraintSystem, PrimeFieldRepr};
use franklin_crypto::bellman::{Field, PrimeField, SynthesisError};
use franklin_crypto::circuit::baby_ecc::EdwardsPoint;
use franklin_crypto::circuit::num::AllocatedNum;

use verkle_tree::ipa_fs::config::IpaConfig;

use crate::circuit::ipa_fs::utils::convert_bits_le;

use super::ipa_fs::circuit::IpaCircuit;
use super::ipa_fs::proof::OptionIpaProof;
use super::ipa_fs::transcript::{Transcript, WrappedTranscript};

pub struct BatchProofCircuit<'a, 'b, E: JubjubEngine> {
    pub transcript_params: Option<E::Fr>,
    pub proof: OptionIpaProof<E>,
    pub d: Option<edwards::Point<E, Unknown>>,
    pub commitments: Vec<Option<edwards::Point<E, Unknown>>>,
    pub ys: Vec<Option<E::Fs>>,
    pub zs: Vec<Option<usize>>,
    pub ipa_conf: &'a IpaConfig<'b, E>,
    pub jubjub_params: &'a E::Params,
}

impl<'a, 'b, E: JubjubEngine> Circuit<E> for BatchProofCircuit<'a, 'b, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let transcript_params = self.transcript_params;
        dbg!(transcript_params);
        let wrapped_transcript_params =
            AllocatedNum::<E>::alloc(cs.namespace(|| "alloc transcript_params"), || {
                transcript_params.ok_or(SynthesisError::UnconstrainedVariable)
            })?;
        let mut transcript = WrappedTranscript::new(cs, wrapped_transcript_params);

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
                let commitment_x = AllocatedNum::alloc(cs.namespace(|| "alloc Q_x"), || {
                    raw_commitment
                        .0
                        .ok_or(SynthesisError::UnconstrainedVariable)
                })?;
                let commitment_y = AllocatedNum::alloc(cs.namespace(|| "alloc Q_y"), || {
                    raw_commitment
                        .1
                        .ok_or(SynthesisError::UnconstrainedVariable)
                })?;

                EdwardsPoint::interpret(
                    cs.namespace(|| "interpret Q"),
                    &commitment_x,
                    &commitment_y,
                    self.jubjub_params,
                )?
            };

            transcript.commit_point(cs, &allocated_commitment_i)?; // commitments[i]
            allocated_commitment.push(allocated_commitment_i);
            let zi = self.zs[i]
                .map(|zi| E::Fs::from_repr(<E::Fs as PrimeField>::Repr::from(zi as u64)).unwrap());
            transcript.commit_field_element(cs, &zi)?; // z
            transcript.commit_field_element(cs, &self.ys[i])?; // y
        }

        let r = transcript.get_challenge(cs)?;

        let allocated_d = {
            let raw_commitment = if let Some(d) = self.d.clone() {
                let (x, y) = d.into_xy();
                (Some(x), Some(y))
            } else {
                (None, None)
            };
            let commitment_x = AllocatedNum::alloc(cs.namespace(|| "alloc Q_x"), || {
                raw_commitment
                    .0
                    .ok_or(SynthesisError::UnconstrainedVariable)
            })?;
            let commitment_y = AllocatedNum::alloc(cs.namespace(|| "alloc Q_y"), || {
                raw_commitment
                    .1
                    .ok_or(SynthesisError::UnconstrainedVariable)
            })?;

            EdwardsPoint::interpret(
                cs.namespace(|| "interpret Q"),
                &commitment_x,
                &commitment_y,
                self.jubjub_params,
            )?
        };
        transcript.commit_point(cs, &allocated_d)?; // D
        let t = transcript.get_challenge(cs)?;

        // Compute helper_scalars. This is r^i / t - z_i
        //
        // There are more optimal ways to do this, but
        // this is more readable, so will leave for now
        let mut helper_scalars: Vec<Option<E::Fs>> = Vec::with_capacity(num_queries);
        let mut powers_of_r = E::Fs::one(); // powers_of_r = 1
        for i in 0..num_queries {
            // helper_scalars[i] = r^i / (t - z_i)
            let helper_scalars_i = if let (Some(zi), Some(t)) = (self.zs[i], t) {
                let zi = E::Fs::from_repr(<E::Fs as PrimeField>::Repr::from(zi as u64)).unwrap();
                let mut t_minus_z_i = t;
                t_minus_z_i.sub_assign(&zi);
                let mut helper_scalars_i = t_minus_z_i.inverse().unwrap();
                helper_scalars_i.mul_assign(&powers_of_r);

                Some(helper_scalars_i)
            } else {
                None
            };

            helper_scalars.push(helper_scalars_i);

            // powers_of_r *= r
            if let Some(r) = r {
                powers_of_r.mul_assign(&r);
            }
        }

        // Compute g_2(t) = SUM y_i * (r^i / t - z_i) = SUM y_i * helper_scalars
        let mut g_2_t = E::Fs::zero();
        for (i, helper_scalars_i) in helper_scalars.iter().enumerate() {
            if let (Some(yi), Some(helper_scalars_i)) = (self.ys[i], helper_scalars_i) {
                let mut tmp = yi;
                tmp.mul_assign(helper_scalars_i);
                g_2_t.add_assign(&tmp);
            };
        }

        // Compute E = SUM C_i * (r^i / t - z_i) = SUM C_i * helper_scalars
        assert!(!self.commitments.is_empty(), "`e` must be non-zero.");
        let mut e = {
            let helper_scalars_i_bits = convert_bits_le(cs, helper_scalars[0], None)?;
            allocated_commitment[0].mul(
                cs.namespace(|| "multiply commitment[0] by helper_scalars[0]"),
                &helper_scalars_i_bits,
                self.jubjub_params,
            )?
        };
        for (i, &helper_scalars_i) in helper_scalars.iter().enumerate().skip(1) {
            let helper_scalars_i_bits = convert_bits_le(cs, helper_scalars_i, None)?;
            let mut tmp = allocated_commitment[i].mul(
                cs.namespace(|| format!("multiply commitment[{}] by helper_scalars[{}]", i, i)),
                &helper_scalars_i_bits,
                self.jubjub_params,
            )?;
            e = e.add(cs.namespace(|| ""), &mut tmp, self.jubjub_params)?;
        }

        transcript.commit_point(cs, &e)?; // E

        let mut minus_d = {
            let (minus_d_x, d_y) = if let Some(d) = self.d.clone() {
                let (mut d_x, d_y) = d.into_xy();
                d_x.negate();

                (Some(d_x), Some(d_y))
            } else {
                (None, None)
            };
            let minus_d_x = AllocatedNum::alloc(cs.namespace(|| "alloc -D_x"), || {
                minus_d_x.ok_or(SynthesisError::UnconstrainedVariable)
            })?;
            let d_y = AllocatedNum::alloc(cs.namespace(|| "alloc D_y"), || {
                d_y.ok_or(SynthesisError::UnconstrainedVariable)
            })?;

            EdwardsPoint::interpret(
                cs.namespace(|| "interpret Q"),
                &minus_d_x,
                &d_y,
                self.jubjub_params,
            )?
        };
        let e_minus_d = e.add(
            cs.namespace(|| "subtract d from e"),
            &mut minus_d,
            self.jubjub_params,
        )?;
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
            eval_point: t,
            inner_prod: Some(g_2_t),
            ipa_conf: self.ipa_conf,
            jubjub_params: self.jubjub_params,
            transcript_params,
        };

        ipa.synthesize(cs)
    }
}
