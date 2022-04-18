use franklin_crypto::babyjubjub::{edwards, JubjubEngine, Unknown};
use franklin_crypto::bellman::plonk::better_better_cs::cs::{
    Circuit, ConstraintSystem, Gate, GateInternal, Width4MainGateWithDNext,
};
use franklin_crypto::bellman::{Field, PrimeField, SynthesisError};
use franklin_crypto::plonk::circuit::allocated_num::AllocatedNum;
use franklin_crypto::plonk::circuit::bigint::field::{FieldElement, RnsParameters};
use franklin_crypto::plonk::circuit::bigint::range_constraint_gate::TwoBitDecompositionRangecheckCustomGate;
use verkle_tree::ipa_fs::config::{Committer, IpaConfig};
use verkle_tree::ipa_fs::utils::log2_ceil;

use crate::circuit::ipa_fs::circuit::check_ipa_proof;
use crate::circuit::num::{allocate_edwards_point, convert_bits_le};

use super::ipa_fs::dummy_transcript::WrappedDummyTranscript as WrappedTranscript;
// use super::ipa_fs::transcript::WrappedTranscript;
use super::ipa_fs::proof::OptionIpaProof;
use super::ipa_fs::transcript::Transcript;
use super::num::baby_ecc::EdwardsPoint;

pub struct BatchProofCircuit<'a, 'b, 'c, E: JubjubEngine>
where
    'c: 'b,
{
    // public inputs
    pub transcript_params: Option<E::Fr>,
    pub commitments: Vec<Option<edwards::Point<E, Unknown>>>,

    // private inputs
    pub proof: OptionIpaProof<E>,
    pub d: Option<edwards::Point<E, Unknown>>,
    pub ys: Vec<Option<E::Fs>>,
    pub zs: Vec<Option<usize>>,

    // constant parameters
    pub ipa_conf: &'c IpaConfig<'b, E>,
    pub rns_params: &'a RnsParameters<E, E::Fs>,
}

impl<'a, 'b, 'c, E: JubjubEngine> BatchProofCircuit<'a, 'b, 'c, E>
where
    'c: 'b,
{
    // Initialize variables with None.
    pub fn initialize(
        ipa_conf: &'c IpaConfig<'b, E>,
        rns_params: &'a RnsParameters<E, E::Fs>,
    ) -> Self {
        let num_rounds = log2_ceil(ipa_conf.get_domain_size());

        BatchProofCircuit::<E> {
            transcript_params: None,
            commitments: vec![None; num_rounds],
            proof: OptionIpaProof::with_depth(num_rounds),
            d: None,
            ys: vec![None; num_rounds],
            zs: vec![None; num_rounds],
            ipa_conf,
            rns_params,
        }
    }
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
        let jubjub_params = self.ipa_conf.jubjub_params;
        dbg!(self.transcript_params);
        let transcript_params = AllocatedNum::<E>::alloc(cs, || {
            self.transcript_params
                .ok_or(SynthesisError::UnconstrainedVariable)
        })?;
        // transcript_params.inputize(cs)?;

        dbg!(self
            .commitments
            .iter()
            .map(|v| v.as_ref().map(|v| v.into_xy()))
            .collect::<Vec<_>>());
        let commitments = self
            .commitments
            .iter()
            .map(|ci| {
                let tmp = allocate_edwards_point(cs, &ci, jubjub_params)?;
                // tmp.inputize(cs)?;

                Ok(tmp)
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;
        let ys = self
            .ys
            .iter()
            .map(|&yi| FieldElement::new_allocated_in_field(cs, yi, self.rns_params))
            .collect::<Result<Vec<_>, _>>()?;
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
            .collect::<Result<Vec<_>, _>>()?;
        let d = allocate_edwards_point(cs, &self.d, jubjub_params)?;

        check_batch_proof(
            cs,
            transcript_params,
            commitments,
            &self.proof,
            d,
            ys,
            zs,
            self.ipa_conf,
            self.rns_params,
        )
    }
}

pub fn check_batch_proof<'a, E: JubjubEngine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    transcript_params: AllocatedNum<E>,
    commitments: Vec<EdwardsPoint<E>>,
    proof: &OptionIpaProof<E>,
    d: EdwardsPoint<E>,
    ys: Vec<FieldElement<E, E::Fs>>,
    zs: Vec<FieldElement<E, E::Fs>>,
    ipa_conf: &IpaConfig<'a, E>,
    rns_params: &RnsParameters<E, E::Fs>,
) -> Result<(), SynthesisError> {
    let jubjub_params = ipa_conf.jubjub_params;
    let mut transcript = WrappedTranscript::new(cs, transcript_params);

    let num_queries = commitments.len();
    if num_queries == 0 {
        panic!("cannot create a multi proof with no data");
    }

    assert_eq!(
        ys.len(),
        num_queries,
        "number of output points = {}, while number of commitments = {}",
        ys.len(),
        num_queries,
    );
    assert_eq!(
        zs.len(),
        num_queries,
        "number of input points = {}, while number of commitments = {}",
        zs.len(),
        num_queries,
    );

    for i in 0..num_queries {
        transcript.commit_point(cs, &commitments[i])?;
        transcript.commit_field_element(cs, &zs[i])?;
        transcript.commit_field_element(cs, &ys[i])?;
    }

    let r = transcript.get_challenge(cs, rns_params)?;

    transcript.commit_point(cs, &d)?;
    let t = transcript.get_challenge(cs, rns_params)?;

    // Compute helper_scalars.
    let mut helper_scalars = Vec::with_capacity(num_queries);
    let one = FieldElement::new_constant(E::Fs::one(), rns_params);
    let mut powers_of_r = one.clone(); // powers_of_r = 1
    for zi in zs {
        // helper_scalars[i] = r^i / (t - z_i)
        let t_minus_zi = t.clone().sub(cs, zi.clone())?.0;
        let raw_inv_t_minus_zi = if let Some(raw_t_minus_zi) = t_minus_zi.get_field_value() {
            Some(raw_t_minus_zi.inverse().ok_or("division by zero").unwrap())
        } else {
            None
        };
        let inv_t_minus_zi =
            FieldElement::new_allocated_in_field(cs, raw_inv_t_minus_zi, rns_params)?;
        // inv_t_minus_zi.mul(cs, t_minus_zi)?.assert_equal(cs, one)?;
        let helper_scalars_i = inv_t_minus_zi.mul(cs, powers_of_r.clone())?.0;
        {
            let _helper_scalars_i = powers_of_r.clone().div(cs, t_minus_zi)?.0;
            assert_eq!(
                helper_scalars_i.get_field_value(),
                _helper_scalars_i.get_field_value()
            );
        }
        helper_scalars.push(helper_scalars_i);

        // powers_of_r *= r
        powers_of_r = powers_of_r.mul(cs, r.clone())?.0;
    }

    // Compute g_2(t) = SUM y_i * (r^i / t - z_i) = SUM y_i * helper_scalars
    let mut g_2_t = FieldElement::new_constant(E::Fs::zero(), rns_params);
    for (i, helper_scalars_i) in helper_scalars.iter().enumerate() {
        let tmp = ys[i].clone().mul(cs, helper_scalars_i.clone())?.0;
        g_2_t = g_2_t.add(cs, tmp)?.0;
    }

    // Compute E = SUM C_i * (r^i / t - z_i) = SUM C_i * helper_scalars
    let mut e = {
        let helper_scalars_i_bits = convert_bits_le(cs, helper_scalars[0].clone(), None)?;
        commitments[0].mul(cs, &helper_scalars_i_bits, jubjub_params)?
    };
    for (i, helper_scalars_i) in helper_scalars.iter().enumerate().skip(1) {
        let helper_scalars_i_bits = convert_bits_le(cs, helper_scalars_i.clone(), None)?;
        let tmp = commitments[i].mul(cs, &helper_scalars_i_bits, jubjub_params)?;
        e = e.add(cs, &tmp, jubjub_params)?;
    }

    transcript.commit_point(cs, &e)?;

    // ipa_commitment = E - D
    let minus_d = {
        let d_x = d.get_x();
        let d_y = d.get_y();
        let zero = AllocatedNum::zero(cs);
        let minus_d_x = zero.sub(cs, d_x)?;

        EdwardsPoint::interpret(cs, &minus_d_x, d_y, jubjub_params)?
    };
    let e_minus_d = e.add(cs, &minus_d, jubjub_params)?;

    // let ipa_commitment = if let (Some(x), Some(y)) =
    //     (e_minus_d.get_x().get_value(), e_minus_d.get_y().get_value())
    // {
    //     edwards::Point::get_for_y(y, x.into_repr().is_odd(), jubjub_params)
    // } else {
    //     None
    // };

    check_ipa_proof(
        cs,
        transcript.into_params(),
        e_minus_d,
        proof,
        t,
        g_2_t,
        ipa_conf,
    )?;

    Ok(())
}
