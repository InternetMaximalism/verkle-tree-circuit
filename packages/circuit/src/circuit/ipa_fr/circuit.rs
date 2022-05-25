use std::io::{Error, ErrorKind};

use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::plonk::better_better_cs::cs::{
    Circuit, ConstraintSystem, Gate, GateInternal, Width4MainGateWithDNext,
};
use franklin_crypto::bellman::{Field, SynthesisError};
use franklin_crypto::plonk::circuit::allocated_num::AllocatedNum;
use franklin_crypto::plonk::circuit::bigint::range_constraint_gate::TwoBitDecompositionRangecheckCustomGate;
use franklin_crypto::plonk::circuit::boolean::Boolean;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::aux_data::AuxData;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::WrappedAffinePoint;
use verkle_tree::ipa_fr::config::{Committer, IpaConfig};
use verkle_tree::ipa_fr::rns::BaseRnsParameters;
use verkle_tree::ipa_fr::utils::log2_ceil;

use super::config::compute_barycentric_coefficients;
use super::proof::{generate_challenges, OptionIpaProof};
use super::transcript::{Transcript, WrappedTranscript};
use super::utils::{commit, fold_points, fold_scalars};

#[derive(Clone)]
pub struct IpaCircuit<'a, E: Engine, WP: WrappedAffinePoint<'a, E>, AD: AuxData<E>> {
    pub transcript_params: Option<E::Fr>,
    pub commitment: Option<E::G1Affine>,
    pub proof: OptionIpaProof<E::G1Affine>,
    pub eval_point: Option<E::Fr>,
    pub inner_prod: Option<E::Fr>,
    pub ipa_conf: IpaConfig<E::G1Affine>,
    pub rns_params: &'a BaseRnsParameters<E>,
    pub aux_data: AD,
    pub _wp: std::marker::PhantomData<WP>,
}

impl<'a, E: Engine, WP: WrappedAffinePoint<'a, E>, AD: AuxData<E>> Circuit<E>
    for IpaCircuit<'a, E, WP, AD>
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

        if self.proof.l.len() != self.proof.r.len() {
            return Err(
                Error::new(ErrorKind::InvalidData, "L and R should be the same size").into(),
            );
        }

        let domain_size = self.ipa_conf.get_domain_size();
        let num_rounds = log2_ceil(domain_size) as usize;
        if self.proof.l.len() != num_rounds {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "The number of points for L or R should be equal to the number of rounds",
            )
            .into());
        }

        let eval_point = AllocatedNum::alloc(cs, || Ok(self.eval_point.unwrap()))?;
        let inner_prod = AllocatedNum::alloc(cs, || Ok(self.inner_prod.unwrap()))?;
        let mut commitment = WP::alloc(cs, self.commitment, self.rns_params, &self.aux_data)?;

        let mut b = compute_barycentric_coefficients::<E, CS>(
            cs,
            self.ipa_conf.get_precomputed_weights(),
            &eval_point,
        )
        .unwrap();

        if b.len() != self.ipa_conf.get_srs().len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "`barycentric_coefficients` had incorrect length",
            )
            .into());
        }

        transcript.commit_point(cs, &commitment)?; // C
        transcript.commit_alloc_num(cs, eval_point)?; // input point
        transcript.commit_alloc_num(cs, inner_prod)?; // output point

        let w = transcript.get_challenge();
        let mut q = WP::alloc(
            cs,
            Some(self.ipa_conf.get_q()),
            self.rns_params,
            &self.aux_data,
        )?;
        let mut qw = q.mul::<CS, AD>(cs, &w, None, self.rns_params, &self.aux_data)?;

        let mut qy = qw
            .clone()
            .mul(cs, &inner_prod, None, self.rns_params, &self.aux_data)?;
        commitment = commitment.add(cs, &mut qy, self.rns_params)?;

        let challenges = generate_challenges::<_, _, WP, _>(
            cs,
            self.proof.clone(),
            &mut transcript,
            self.rns_params,
            &self.aux_data,
        )?;

        let mut challenges_inv: Vec<AllocatedNum<E>> = Vec::with_capacity(challenges.len());

        // Compute expected commitment
        for (i, x) in challenges.iter().enumerate() {
            println!("challenges_inv: {}/{}", i, challenges.len());
            let l = WP::alloc(cs, self.proof.l[i], self.rns_params, &self.aux_data)?;
            let r = WP::alloc(cs, self.proof.r[i], self.rns_params, &self.aux_data)?;

            let mut minus_one = E::Fr::one();
            minus_one.negate();
            let x_inv = x.inverse(cs)?;
            challenges_inv.push(x_inv);

            let one = AllocatedNum::one(cs);
            commitment = commit(
                cs,
                &[commitment, l, r],
                &[one, *x, x_inv],
                self.rns_params,
                &self.aux_data,
            )?;
        }

        println!("challenges_inv: {}/{}", challenges.len(), challenges.len());

        let mut current_basis = self
            .ipa_conf
            .get_srs()
            .iter()
            .map(|v| WP::alloc(cs, Some(*v), self.rns_params, &self.aux_data))
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
            current_basis = fold_points::<E, CS, WP, AD>(
                cs,
                &g_l,
                &g_r,
                x_inv,
                self.rns_params,
                &self.aux_data,
            )?;
        }

        println!("x_inv: {}/{}", challenges_inv.len(), challenges_inv.len());

        if b.len() != 1 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "`b` and `current_basis` should be 1",
            )
            .into());
        }

        println!(
            "reduction ends: {} s",
            start.elapsed().as_millis() as f64 / 1000.0
        );

        println!("verification check starts");
        let start = std::time::Instant::now();

        // Compute `result = G[0] * a + (a * b[0]) * Q`.
        let proof_a = AllocatedNum::alloc(cs, || Ok(self.proof.a.unwrap()))?;
        let mut result1 = current_basis[0].clone(); // result1 = G[0]
        let mut part_2a: AllocatedNum<E> = b[0]; // part_2a = b[0]

        // let proof_a_bits = proof_a.into_bits_le(cs)?;
        result1 = result1.mul::<CS, AD>(cs, &proof_a, None, self.rns_params, &self.aux_data)?; // result1 *= proof_a
        part_2a = part_2a.mul(cs, &proof_a)?; // part_2a *= proof_a
        let mut result2 = qw.mul(cs, &part_2a, None, self.rns_params, &self.aux_data)?; // result2 = qw * part_2a
        let result = result1.add(cs, &mut result2, self.rns_params)?; // result = result1 + result2

        // Ensure `commitment` is equal to `result`.
        let is_valid = commitment.equals(cs, &result, self.rns_params)?;

        println!(
            "verification check ends: {} s",
            start.elapsed().as_millis() as f64 / 1000.0
        );

        let allocated_true = Boolean::constant(true);
        Boolean::enforce_equal(cs, &is_valid, &allocated_true)
    }
}
