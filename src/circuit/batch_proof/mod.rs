use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::plonk::better_better_cs::cs::{
    Circuit, ConstraintSystem, Gate, GateInternal, Width4MainGateWithDNext,
};
use franklin_crypto::bellman::{PrimeField, SynthesisError};
use franklin_crypto::plonk::circuit::allocated_num::AllocatedNum;
use franklin_crypto::plonk::circuit::bigint::range_constraint_gate::TwoBitDecompositionRangecheckCustomGate;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::aux_data::AuxData;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::WrappedAffinePoint;
use verkle_tree::ipa_fr::config::IpaConfig;
use verkle_tree::ipa_fr::rns::BaseRnsParameters;

use super::ipa_fr::circuit::IpaCircuit;
use super::ipa_fr::proof::OptionIpaProof;
use super::ipa_fr::transcript::{Transcript, WrappedTranscript};
use super::utils::read_field_element_le_from;

// #[derive(Clone, Debug)]
// pub struct OptionIpaProof<G: CurveProjective> {
//     pub l: Vec<Option<G::Affine>>,
//     pub r: Vec<Option<G::Affine>>,
//     pub a: Option<G::Scalar>,
// }

pub struct BatchProofCircuit<'a, E: Engine, WP: WrappedAffinePoint<'a, E>, AD: AuxData<E>> {
    pub transcript_params: Option<E::Fr>,
    pub proof: OptionIpaProof<E::G1>,
    pub d: Option<E::G1Affine>,
    pub commitments: Vec<Option<E::G1Affine>>,
    pub ys: Vec<Option<E::Fr>>,
    pub zs: Vec<Option<u8>>,
    pub ipa_conf: IpaConfig<E::G1>,
    pub rns_params: &'a BaseRnsParameters<E>,
    pub aux_data: AD,
    pub _wp: std::marker::PhantomData<WP>,
}

impl<'a, E: Engine, WP: WrappedAffinePoint<'a, E>, AD: AuxData<E>> Circuit<E>
    for BatchProofCircuit<'a, E, WP, AD>
{
    type MainGate = Width4MainGateWithDNext;

    fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
        Ok(vec![
            Self::MainGate::default().into_internal(),
            TwoBitDecompositionRangecheckCustomGate::default().into_internal(),
        ])
    }

    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        let transcript_params = AllocatedNum::alloc(cs, || Ok(self.transcript_params.unwrap()))?;
        let mut transcript = WrappedTranscript::new(transcript_params);
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
            panic!("cannot create a multi proof with no data");
        }

        for i in 0..num_queries {
            let allocated_commitment_i =
                WP::alloc::<CS, AD>(cs, self.commitments[i], self.rns_params, &self.aux_data)?;
            transcript.commit_point(cs, &allocated_commitment_i)?; // commitments[i]
            let zi = self.zs[i]
                .map(|zi| E::Fr::from_repr(<E::Fr as PrimeField>::Repr::from(zi as u64)).unwrap());
            let allocated_zi = AllocatedNum::alloc(cs, || Ok(zi.unwrap()))?;
            transcript.commit_alloc_num(cs, allocated_zi)?;
            let allocated_yi = AllocatedNum::alloc(cs, || Ok(self.ys[i].unwrap()))?;
            transcript.commit_alloc_num(cs, allocated_yi)?;
            // y
        }

        let r = transcript.get_challenge();

        let allocated_d = WP::alloc::<CS, AD>(cs, self.d, self.rns_params, &self.aux_data)?;
        transcript.commit_point(cs, &allocated_d)?; // D
        let t = transcript.get_challenge();

        // Compute helper_scalars. This is r^i / t - z_i
        //
        // There are more optimal ways to do this, but
        // this is more readable, so will leave for now
        let mut helper_scalars: Vec<AllocatedNum<E>> = Vec::with_capacity(num_queries);
        let mut powers_of_r = AllocatedNum::one::<CS>(cs); // powers_of_r = 1
        for i in 0..num_queries {
            // helper_scalars[i] = r^i / (t - z_i)
            let z_i: AllocatedNum<E> = AllocatedNum::alloc(cs, || {
                self.zs[i]
                    .map(|v| {
                        let mut reader = std::io::Cursor::new(vec![v]);
                        read_field_element_le_from::<E::Fr, _>(&mut reader).unwrap()
                    })
                    .ok_or(SynthesisError::Unsatisfiable)
            })?;
            let t_minus_z_i = t.sub(cs, &z_i)?;
            let inverse_of_t_minus_z_i = t_minus_z_i.inverse(cs)?;
            let helper_scalars_i = inverse_of_t_minus_z_i.mul(cs, &powers_of_r)?;
            helper_scalars.push(helper_scalars_i);

            // powers_of_r *= r
            powers_of_r = powers_of_r.mul(cs, &r)?;
        }

        // Compute g_2(t) = SUM y_i * (r^i / t - z_i) = SUM y_i * helper_scalars
        let mut g_2_t: AllocatedNum<E> = AllocatedNum::zero(cs);
        for (i, helper_scalars_i) in helper_scalars.iter().enumerate() {
            let mut tmp = AllocatedNum::alloc(cs, || Ok(self.ys[i].unwrap()))?;
            tmp = tmp.mul(cs, helper_scalars_i)?;
            g_2_t = g_2_t.add(cs, &tmp)?;
        }

        // Compute E = SUM C_i * (r^i / t - z_i) = SUM C_i * helper_scalars
        assert!(!self.commitments.is_empty(), "`e` must be non-zero.");
        let mut e = WP::alloc(cs, self.commitments[0], self.rns_params, &self.aux_data)?;
        for (i, helper_scalars_i) in helper_scalars.iter().enumerate().skip(1) {
            let mut tmp = WP::alloc(cs, self.commitments[i], self.rns_params, &self.aux_data)?;
            tmp = tmp.mul(cs, helper_scalars_i, None, self.rns_params, &self.aux_data)?;
            e = e.add(cs, &mut tmp, self.rns_params)?;
        }

        transcript.commit_point(cs, &e)?; // E

        let mut d = WP::alloc(cs, self.d, self.rns_params, &self.aux_data)?;
        let mut minus_d = d.negate(cs, self.rns_params)?;
        let e_minus_d = e.add(cs, &mut minus_d, self.rns_params)?;

        let transcript_params = transcript.get_challenge();
        let ipa = IpaCircuit::<'_, E, WP, AD> {
            commitment: e_minus_d.get_point().get_value(),
            proof: self.proof.clone(),
            eval_point: t.get_value(),
            inner_prod: g_2_t.get_value(),
            ipa_conf: self.ipa_conf.clone(),
            rns_params: self.rns_params,
            aux_data: self.aux_data.clone(),
            transcript_params: transcript_params.get_value(),
            _wp: std::marker::PhantomData,
        };

        ipa.synthesize(cs)
    }
}
