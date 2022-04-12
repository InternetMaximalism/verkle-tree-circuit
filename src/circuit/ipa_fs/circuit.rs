// use std::io::{Error, ErrorKind};

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

use crate::circuit::ipa_fs::config::compute_barycentric_coefficients;
use crate::circuit::num::{allocate_edwards_point, convert_bits_le};

use super::dummy_transcript::WrappedDummyTranscript as WrappedTranscript;
// use super::transcript::WrappedTranscript;
use super::proof::{generate_challenges, OptionIpaProof};
use super::transcript::Transcript;
use super::utils::{fold_points, fold_scalars};

#[derive(Clone)]
pub struct IpaCircuit<'a, 'b, 'c, E: JubjubEngine>
where
    'c: 'b,
{
    pub transcript_params: Option<E::Fr>,
    pub commitment: Option<edwards::Point<E, Unknown>>,
    pub proof: OptionIpaProof<E>,
    pub eval_point: Option<E::Fs>,
    pub inner_prod: Option<E::Fs>,
    pub ipa_conf: &'c IpaConfig<'b, E>,
    pub rns_params: &'a RnsParameters<E, <E as JubjubEngine>::Fs>,
    pub jubjub_params: &'a E::Params,
}

impl<'a, 'b, 'c, E: JubjubEngine> Circuit<E> for IpaCircuit<'a, 'b, 'c, E>
where
    'c: 'b,
{
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
        // transcript.consume("ipa", cs);

        // println!("{:?}", self.proof);
        assert_eq!(
            self.proof.l.len(),
            self.proof.r.len(),
            "L and R should be the same size"
        );

        let num_ipa_rounds = log2_ceil(self.ipa_conf.get_domain_size());
        assert_eq!(
            self.proof.l.len(),
            num_ipa_rounds,
            "The number of points for L or R should be equal to the number of rounds"
        );

        let eval_point =
            FieldElement::new_allocated_in_field(cs, self.eval_point, self.rns_params)?;
        let inner_prod =
            FieldElement::new_allocated_in_field(cs, self.inner_prod, self.rns_params)?;
        let mut commitment = allocate_edwards_point(cs, &self.commitment, self.jubjub_params)?;
        dbg!(commitment.get_x().get_value());
        dbg!(commitment.get_y().get_value());

        // let bit_limit = None; // Some(256usize);
        let mut b = compute_barycentric_coefficients::<E, CS>(
            cs,
            &self.ipa_conf.precomputed_weights,
            &eval_point,
        )?;
        dbg!(b
            .iter()
            .map(|b| b.get_field_value().map(|v| v.into_repr()))
            .collect::<Vec<_>>());
        assert_eq!(
            b.len(),
            self.ipa_conf.srs.len(),
            "`barycentric_coefficients` had incorrect length"
        );

        transcript.commit_point(cs, &commitment)?;
        transcript.commit_field_element(cs, &eval_point)?;
        transcript.commit_field_element(cs, &inner_prod)?;

        let w = transcript.get_challenge(cs, self.rns_params)?;
        dbg!(w.get_field_value().map(|v| v.into_repr()));

        let q = allocate_edwards_point(cs, &Some(self.ipa_conf.q.clone()), self.jubjub_params)?;

        let w_bits = convert_bits_le(cs, w, None)?;
        let qw = q.mul(cs, &w_bits, self.jubjub_params)?;
        dbg!(qw.get_x().get_value());
        dbg!(qw.get_y().get_value());
        let inner_prod_bits = convert_bits_le(cs, inner_prod, None)?;
        let qy = qw.mul(cs, &inner_prod_bits, self.jubjub_params)?;
        dbg!(qy.get_x().get_value());
        dbg!(qy.get_y().get_value());
        commitment = commitment.add(cs, &qy, self.jubjub_params)?;
        dbg!(commitment.get_x().get_value());
        dbg!(commitment.get_y().get_value());

        let (challenges, wrapped_proof) = generate_challenges(
            cs,
            &self.proof.clone(),
            &mut transcript,
            self.jubjub_params,
            self.rns_params,
        )
        .unwrap();

        let mut challenges_inv = Vec::with_capacity(challenges.len());

        // Compute expected commitment
        for (i, x) in challenges.iter().enumerate() {
            dbg!(x.get_field_value().map(|v| v.into_repr()));
            println!("challenges_inv: {}/{}", i, challenges.len());
            let l = wrapped_proof.l[i].clone();
            let r = wrapped_proof.r[i].clone();

            let x_inv = {
                let raw_x_inv = x.get_field_value().map(|raw_x| raw_x.inverse().unwrap());
                let x_inv = FieldElement::new_allocated_in_field(cs, raw_x_inv, self.rns_params)?;

                x_inv
            };
            challenges_inv.push(x_inv.clone());

            // let one = E::Fs::one();
            let x_bits = convert_bits_le(cs, x.clone(), None)?;
            let commitment_l = l.mul(cs, &x_bits, self.jubjub_params)?;
            let x_inv_bits = convert_bits_le(cs, x_inv, None)?;
            let commitment_r = r.mul(cs, &x_inv_bits, self.jubjub_params)?;
            commitment = commitment.add(cs, &commitment_l, self.jubjub_params)?.add(
                cs,
                &commitment_r,
                self.jubjub_params,
            )?;
            // commitment = commit(
            //     &mut cs.namespace(|| "commit"),
            //     &[commitment, l, r],
            //     &[Some(one), x.clone(), x_inv],
            //     self.jubjub_params,
            // )?;
            dbg!(commitment.get_x().get_value());
            dbg!(commitment.get_y().get_value());
        }

        println!("challenges_inv: {}/{}", challenges.len(), challenges.len());

        let mut current_basis = self
            .ipa_conf
            .srs
            .iter()
            .map(|v| allocate_edwards_point(cs, &Some(v.clone()), self.jubjub_params))
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

            dbg!(x_inv.get_field_value().map(|v| v.into_repr()));
            b = fold_scalars(cs, &b_l, &b_r, x_inv).unwrap();
            current_basis = fold_points::<E, CS>(cs, &g_l, &g_r, x_inv, self.jubjub_params)?;
        }

        println!("x_inv: {}/{}", challenges_inv.len(), challenges_inv.len());

        assert_eq!(
            b.len(),
            1,
            "`b` and `current_basis` should have one element by the reduction."
        );

        println!(
            "reduction ends: {} s",
            start.elapsed().as_millis() as f64 / 1000.0
        );

        println!("verification check starts");
        let start = std::time::Instant::now();

        // Compute `result = G[0] * a + (a * b[0]) * Q`.
        let proof_a = FieldElement::new_allocated_in_field(cs, wrapped_proof.a, self.rns_params)?;
        let mut result1 = current_basis[0].clone(); // result1 = G[0]
        dbg!(current_basis[0].get_x().get_value());
        dbg!(current_basis[0].get_y().get_value());

        let part_2a = b[0].clone(); // part_2a = b[0]
        dbg!(b[0].get_field_value().map(|v| v.into_repr()));

        let proof_a_bits = convert_bits_le(cs, proof_a.clone(), None)?;
        result1 = result1.mul(cs, &proof_a_bits, self.jubjub_params)?; // result1 = a[0] * current_basis[0]
        dbg!(result1.get_x().get_value());
        dbg!(result1.get_y().get_value());

        let part_2a = {
            let (part_2a, (_, _)) = part_2a.mul(cs, proof_a)?; // part_2a = a[0] * b[0]

            part_2a
        };
        dbg!(part_2a.get_field_value().map(|v| v.into_repr()));

        let part_2a_bits = convert_bits_le(cs, part_2a, None)?;
        let result2 = qw.mul(cs, &part_2a_bits, self.jubjub_params)?; // result2 = a[0] * b[0] * w * Q
        dbg!(result2.get_x().get_value());
        dbg!(result2.get_y().get_value());

        let result = result1.add(cs, &result2, self.jubjub_params)?; // result = result1 + result2
        dbg!(result.get_x().get_value());
        dbg!(result.get_y().get_value());

        // Ensure `commitment` is equal to `result`.
        commitment.get_x().enforce_equal(cs, result.get_x())?;
        commitment.get_y().enforce_equal(cs, result.get_y())?;

        println!(
            "verification check ends: {} s",
            start.elapsed().as_millis() as f64 / 1000.0
        );

        Ok(())
    }
}
