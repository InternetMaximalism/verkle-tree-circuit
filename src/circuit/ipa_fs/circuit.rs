use std::io::{Error, ErrorKind};

use franklin_crypto::babyjubjub::{edwards, JubjubEngine, Unknown};
use franklin_crypto::bellman::{Circuit, ConstraintSystem};
use franklin_crypto::bellman::{Field, SynthesisError};
use franklin_crypto::circuit::baby_ecc::EdwardsPoint;
use franklin_crypto::circuit::num::AllocatedNum;
use verkle_tree::ipa_fs::config::{Committer, IpaConfig};
use verkle_tree::ipa_fs::utils::log2_ceil;

use crate::circuit::ipa_fs::config::compute_barycentric_coefficients;
use crate::circuit::ipa_fs::transcript::convert_fs_to_fr;
use crate::circuit::ipa_fs::utils::convert_bits_le;

use super::proof::{generate_challenges, OptionIpaProof};
use super::transcript::{Transcript, WrappedTranscript};
use super::utils::{commit, fold_points, fold_scalars};

#[derive(Clone)]
pub struct IpaCircuit<'a, E: JubjubEngine> {
    pub transcript_params: E::Fs,
    pub commitment: Option<edwards::Point<E, Unknown>>,
    pub proof: OptionIpaProof<E>,
    pub eval_point: Option<E::Fs>,
    pub inner_prod: Option<E::Fs>,
    pub ipa_conf: IpaConfig<E>,
    pub jubjub_params: &'a E::Params,
}

impl<'a, E: JubjubEngine> Circuit<E> for IpaCircuit<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let transcript_params = convert_fs_to_fr::<E>(&self.transcript_params).unwrap();
        let wrapped_transcript_params =
            AllocatedNum::<E>::alloc(cs.namespace(|| "alloc transcript_params"), || {
                Ok(transcript_params)
            })?;
        let mut transcript = WrappedTranscript::new(cs, wrapped_transcript_params);
        // transcript.consume("ipa", cs);

        // println!("{:?}", self.proof);
        if self.proof.l.len() != self.proof.r.len() {
            return Err(
                Error::new(ErrorKind::InvalidData, "L and R should be the same size").into(),
            );
        }

        let num_ipa_rounds = log2_ceil(self.ipa_conf.get_domain_size());
        if self.proof.l.len() != num_ipa_rounds {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "The number of points for L or R should be equal to the number of rounds",
            )
            .into());
        }

        let eval_point = self.eval_point;
        let inner_prod = self.inner_prod;
        let raw_commitment = if let Some(c) = self.commitment {
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
        let mut commitment = EdwardsPoint::interpret(
            cs.namespace(|| "interpret Q"),
            &commitment_x,
            &commitment_y,
            self.jubjub_params,
        )?;

        // let bit_limit = None; // Some(256usize);
        let mut b =
            compute_barycentric_coefficients(cs, &self.ipa_conf.precomputed_weights, &eval_point)?;

        if b.len() != self.ipa_conf.srs.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "`barycentric_coefficients` had incorrect length",
            )
            .into());
        }

        transcript.commit_point(cs, &commitment)?;
        transcript.commit_field_element(cs, &eval_point)?;
        transcript.commit_field_element(cs, &inner_prod)?;

        let w = transcript.get_challenge(cs)?;

        let raw_q = self.ipa_conf.q.into_xy();
        let q_x = AllocatedNum::alloc(cs.namespace(|| "alloc Q_x"), || Ok(raw_q.0))?;
        let q_y = AllocatedNum::alloc(cs.namespace(|| "alloc Q_y"), || Ok(raw_q.1))?;
        let mut q = EdwardsPoint::interpret(
            cs.namespace(|| "interpret Q"),
            &q_x,
            &q_y,
            self.jubjub_params,
        )?;

        let mut qy = q.clone();
        let w_bits = convert_bits_le(cs, w, None)?;
        q = q.mul(
            cs.namespace(|| "multiply q by w"),
            &w_bits,
            self.jubjub_params,
        )?;

        let inner_prod_bits = convert_bits_le(cs, inner_prod, None)?;
        qy = qy.mul(
            cs.namespace(|| "qy_mul_inner_prod"),
            &inner_prod_bits,
            self.jubjub_params,
        )?;
        commitment = commitment.add(
            cs.namespace(|| "add qy to commitment"),
            &qy,
            self.jubjub_params,
        )?;

        let (challenges, wrapped_proof) =
            generate_challenges(cs, &self.proof.clone(), &mut transcript, self.jubjub_params)
                .unwrap();

        let mut challenges_inv = Vec::with_capacity(challenges.len());

        // Compute expected commitment
        for (i, x) in challenges.iter().enumerate() {
            println!("challenges_inv: {}/{}", i, challenges.len());
            let l = wrapped_proof.l[i].clone();
            let r = wrapped_proof.r[i].clone();

            let mut minus_one = E::Fr::one();
            minus_one.negate();
            let x_inv = x.map(|v| v.inverse().unwrap());
            challenges_inv.push(x_inv.clone());

            let one = E::Fs::one();
            commitment = commit(
                &mut cs.namespace(|| "commit"),
                &[commitment, l, r],
                &[Some(one), x.clone(), x_inv],
                self.jubjub_params,
            )?;
        }

        println!("challenges_inv: {}/{}", challenges.len(), challenges.len());

        let mut current_basis = self
            .ipa_conf
            .srs
            .iter()
            .map(|v| {
                let raw_v = v.into_xy();
                let v_x = AllocatedNum::alloc(cs.namespace(|| "alloc v_x"), || Ok(raw_v.0))?;
                let v_y = AllocatedNum::alloc(cs.namespace(|| "alloc v_y"), || Ok(raw_v.1))?;
                EdwardsPoint::interpret(
                    cs.namespace(|| "interpret v"),
                    &v_x,
                    &v_y,
                    self.jubjub_params,
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

            b = fold_scalars(cs, &b_l, &b_r, x_inv).unwrap();
            current_basis = fold_points::<E, CS>(cs, &g_l, &g_r, x_inv, self.jubjub_params)?;
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
        let proof_a = wrapped_proof.a;
        let mut result1 = current_basis[0].clone(); // result1 = G[0]
        let mut part_2a = b[0].clone(); // part_2a = b[0]

        let proof_a_bits = convert_bits_le(cs, proof_a, None)?;
        result1 = result1.mul(
            cs.namespace(|| "alloc proof_a"),
            &proof_a_bits,
            self.jubjub_params,
        )?; // result1 *= proof_a

        if let (Some(part_2a), Some(proof_a)) = (&mut part_2a, proof_a) {
            part_2a.mul_assign(&proof_a); // part_2a *= proof_a
        }
        let part_2a_bits = convert_bits_le(cs, part_2a, None)?;
        let result2 = q.mul(
            cs.namespace(|| "multiply q by part_2a_bits"),
            &part_2a_bits,
            self.jubjub_params,
        )?; // q *= part_2a

        let result = result1.add(
            cs.namespace(|| "add result1 to result2"),
            &result2,
            self.jubjub_params,
        )?; // result = result1 + result2

        // Ensure `commitment` is equal to `result`.
        commitment
            .get_x()
            .sub(
                cs.namespace(|| "sub result_x from commitment_x"),
                result.get_x(),
            )?
            .assert_zero(cs.namespace(|| "ensure commitment_x is equal to result_x"))?;
        commitment
            .get_y()
            .sub(
                cs.namespace(|| "sub result_y from commitment_y"),
                result.get_y(),
            )?
            .assert_zero(cs.namespace(|| "ensure commitment_y is equal to result_y"))?;

        println!(
            "verification check ends: {} s",
            start.elapsed().as_millis() as f64 / 1000.0
        );

        Ok(())
    }
}
