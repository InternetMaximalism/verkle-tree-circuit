// use std::io::{Error, ErrorKind};

use franklin_crypto::babyjubjub::{edwards, JubjubEngine, Unknown};
use franklin_crypto::bellman::{Circuit, ConstraintSystem};
use franklin_crypto::bellman::{Field, PrimeField, SynthesisError};
use franklin_crypto::circuit::baby_ecc::EdwardsPoint;
use franklin_crypto::circuit::num::AllocatedNum;
use verkle_tree::ipa_fs::config::{Committer, IpaConfig};
use verkle_tree::ipa_fs::utils::log2_ceil;

use crate::circuit::ipa_fs::config::compute_barycentric_coefficients;
use crate::circuit::ipa_fs::utils::convert_bits_le;

use super::proof::{generate_challenges, OptionIpaProof};
use super::transcript::{Transcript, WrappedTranscript};
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
    pub jubjub_params: &'a E::Params,
}

impl<'a, 'b, 'c, E: JubjubEngine> Circuit<E> for IpaCircuit<'a, 'b, 'c, E>
where
    'c: 'b,
{
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let transcript_params = self.transcript_params;
        dbg!(transcript_params);
        let wrapped_transcript_params =
            AllocatedNum::<E>::alloc(cs.namespace(|| "alloc transcript_params"), || {
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

        let eval_point = self.eval_point;
        let inner_prod = self.inner_prod;
        let mut commitment = {
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

            EdwardsPoint::interpret(
                cs.namespace(|| "interpret Q"),
                &commitment_x,
                &commitment_y,
                self.jubjub_params,
            )?
        };

        dbg!(commitment.get_x().get_value());
        dbg!(commitment.get_y().get_value());

        // let bit_limit = None; // Some(256usize);
        let mut b =
            compute_barycentric_coefficients(cs, &self.ipa_conf.precomputed_weights, &eval_point)?;

        assert_eq!(
            b.len(),
            self.ipa_conf.srs.len(),
            "`barycentric_coefficients` had incorrect length"
        );

        transcript.commit_point(cs, &commitment)?;
        transcript.commit_field_element(cs, &eval_point)?;
        transcript.commit_field_element(cs, &inner_prod)?;

        let w = transcript.get_challenge(cs)?;
        dbg!(w.map(|v| v.into_repr()));

        let q = {
            let raw_q = self.ipa_conf.q.into_xy();
            let q_x = AllocatedNum::alloc(cs.namespace(|| "alloc Q_x"), || Ok(raw_q.0))?;
            let q_y = AllocatedNum::alloc(cs.namespace(|| "alloc Q_y"), || Ok(raw_q.1))?;
            EdwardsPoint::interpret(
                cs.namespace(|| "interpret Q"),
                &q_x,
                &q_y,
                self.jubjub_params,
            )?
        };

        let w_bits = convert_bits_le(cs, w, None)?;
        let qw = q.mul(
            cs.namespace(|| "multiply q by w"),
            &w_bits,
            self.jubjub_params,
        )?;
        dbg!(qw.get_x().get_value());
        dbg!(qw.get_y().get_value());
        let inner_prod_bits = convert_bits_le(cs, inner_prod, None)?;
        let qy = qw.mul(
            cs.namespace(|| "qy_mul_inner_prod"),
            &inner_prod_bits,
            self.jubjub_params,
        )?;
        dbg!(qy.get_x().get_value());
        dbg!(qy.get_y().get_value());
        commitment = commitment.add(
            cs.namespace(|| "add qy to commitment"),
            &qy,
            self.jubjub_params,
        )?;
        dbg!(commitment.get_x().get_value());
        dbg!(commitment.get_y().get_value());

        let (challenges, wrapped_proof) =
            generate_challenges(cs, &self.proof.clone(), &mut transcript, self.jubjub_params)
                .unwrap();

        let mut challenges_inv = Vec::with_capacity(challenges.len());

        // Compute expected commitment
        for (i, x) in challenges.iter().enumerate() {
            dbg!(x.map(|v| v.into_repr()));
            println!("challenges_inv: {}/{}", i, challenges.len());
            let l = wrapped_proof.l[i].clone();
            let r = wrapped_proof.r[i].clone();

            // let mut minus_one = E::Fr::one();
            // minus_one.negate();
            let x_inv = x.map(|v| v.inverse().unwrap());
            challenges_inv.push(x_inv.clone());

            // let one = E::Fs::one();
            let x_bits = convert_bits_le(cs, x.clone(), None)?;
            let commitment_l = l.mul(
                cs.namespace(|| format!("multiply l[{}] by x", i)),
                &x_bits,
                self.jubjub_params,
            )?;
            let x_inv_bits = convert_bits_le(cs, x_inv, None)?;
            let commitment_r = r.mul(
                cs.namespace(|| format!("multiply r[{}] by x^-1", i)),
                &x_inv_bits,
                self.jubjub_params,
            )?;
            commitment = commitment
                .add(
                    cs.namespace(|| format!("add commitment[{}]_l to commitment", i)),
                    &commitment_l,
                    self.jubjub_params,
                )?
                .add(
                    cs.namespace(|| format!("add commitment[{}]_r to commitment", i)),
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

            dbg!(x_inv.map(|v| v.into_repr()));
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
        let proof_a = wrapped_proof.a;
        let mut result1 = current_basis[0].clone(); // result1 = G[0]
        dbg!(result1.get_x().get_value());
        dbg!(result1.get_y().get_value());

        let mut part_2a = b[0].clone(); // part_2a = b[0]
        dbg!(part_2a.map(|v| v.into_repr()));

        let proof_a_bits = convert_bits_le(cs, proof_a, None)?;
        result1 = result1.mul(
            cs.namespace(|| "alloc proof_a"),
            &proof_a_bits,
            self.jubjub_params,
        )?; // result1 = a[0] * current_basis[0]
        dbg!(result1.get_x().get_value());
        dbg!(result1.get_y().get_value());

        if let (Some(part_2a), Some(proof_a)) = (&mut part_2a, proof_a) {
            part_2a.mul_assign(&proof_a); // part_2a = a[0] * b[0]
        }
        dbg!(part_2a.map(|v| v.into_repr()));

        let part_2a_bits = convert_bits_le(cs, part_2a, None)?;
        let result2 = qw.mul(
            cs.namespace(|| "multiply qw by part_2a_bits"),
            &part_2a_bits,
            self.jubjub_params,
        )?; // result2 = a[0] * b[0] * w * Q
        dbg!(result2.get_x().get_value());
        dbg!(result2.get_y().get_value());

        let result = result1.add(
            cs.namespace(|| "add result1 to result2"),
            &result2,
            self.jubjub_params,
        )?; // result = result1 + result2

        dbg!(result.get_x().get_value());
        dbg!(result.get_y().get_value());

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
