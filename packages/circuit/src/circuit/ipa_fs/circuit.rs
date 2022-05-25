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
use crate::circuit::num::baby_ecc::EdwardsPoint;
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
    // public inputs
    pub transcript_params: Option<E::Fr>,
    pub commitment: Option<edwards::Point<E, Unknown>>,

    // private inputs
    pub proof: OptionIpaProof<E>,
    pub eval_point: Option<E::Fs>,
    pub inner_prod: Option<E::Fs>,

    // constant parameters
    pub ipa_conf: &'c IpaConfig<'b, E>,
    pub rns_params: &'a RnsParameters<E, <E as JubjubEngine>::Fs>,
}

impl<'a, 'b, 'c, E: JubjubEngine> IpaCircuit<'a, 'b, 'c, E>
where
    'c: 'b,
{
    pub fn initialize(
        ipa_conf: &'c IpaConfig<'b, E>,
        rns_params: &'a RnsParameters<E, E::Fs>,
    ) -> IpaCircuit<'a, 'b, 'c, E> {
        let num_rounds = log2_ceil(ipa_conf.get_domain_size());

        IpaCircuit::<E> {
            transcript_params: None,
            commitment: None,
            proof: OptionIpaProof::with_depth(num_rounds),
            eval_point: None,
            inner_prod: None,
            ipa_conf,
            rns_params,
        }
    }
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
        let jubjub_params = self.ipa_conf.jubjub_params;

        dbg!(self.transcript_params);
        let allocated_transcript_params = AllocatedNum::<E>::alloc(cs, || {
            self.transcript_params
                .ok_or(SynthesisError::UnconstrainedVariable)
        })?;

        let commitment = allocate_edwards_point(cs, &self.commitment, jubjub_params)?;
        dbg!(commitment.get_x().get_value());
        dbg!(commitment.get_y().get_value());
        commitment.inputize(cs)?;

        let eval_point =
            FieldElement::new_allocated_in_field(cs, self.eval_point, self.rns_params)?;
        let inner_prod =
            FieldElement::new_allocated_in_field(cs, self.inner_prod, self.rns_params)?;

        check_ipa_proof(
            cs,
            allocated_transcript_params,
            commitment,
            &self.proof.clone(),
            eval_point,
            inner_prod,
            self.ipa_conf,
        )
    }
}

pub fn check_ipa_proof<'a, E: JubjubEngine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    transcript_params: AllocatedNum<E>,
    allocated_commitment: EdwardsPoint<E>,
    proof: &OptionIpaProof<E>, // TODO: allocate
    eval_point: FieldElement<E, E::Fs>,
    inner_prod: FieldElement<E, E::Fs>,
    ipa_conf: &IpaConfig<'a, E>,
) -> Result<(), SynthesisError> {
    let jubjub_params = ipa_conf.jubjub_params;
    let rns_params = eval_point.representation_params;

    let mut transcript = WrappedTranscript::new(cs, transcript_params);

    // dbg!(proof);
    let num_ipa_rounds = log2_ceil(ipa_conf.get_domain_size());
    assert_eq!(
        proof.l.len(),
        num_ipa_rounds,
        "The number of points for L should be equal to the number of rounds"
    );
    assert_eq!(
        proof.r.len(),
        num_ipa_rounds,
        "The number of points for R should be equal to the number of rounds"
    );

    let mut b =
        compute_barycentric_coefficients::<E, CS>(cs, &ipa_conf.precomputed_weights, &eval_point)?;
    dbg!(b
        .iter()
        .map(|b| b.get_field_value().map(|v| v.into_repr()))
        .collect::<Vec<_>>());
    assert_eq!(
        b.len(),
        ipa_conf.srs.len(),
        "`barycentric_coefficients` had incorrect length"
    );

    transcript.commit_point(cs, &allocated_commitment)?;
    transcript.commit_field_element(cs, &eval_point)?;
    transcript.commit_field_element(cs, &inner_prod)?;

    let w = transcript.get_challenge(cs, rns_params)?;
    dbg!(w.get_field_value().map(|v| v.into_repr()));

    let q = allocate_edwards_point(cs, &Some(ipa_conf.q.clone()), jubjub_params)?;

    let w_bits = convert_bits_le(cs, w, None)?;
    let qw = q.mul(cs, &w_bits, jubjub_params)?;
    dbg!(qw.get_x().get_value());
    dbg!(qw.get_y().get_value());
    dbg!(inner_prod.get_field_value().map(|v| v.into_repr()));
    let inner_prod_bits = convert_bits_le(cs, inner_prod, None)?;
    let qy = qw.mul(cs, &inner_prod_bits, jubjub_params)?;
    dbg!(qy.get_x().get_value());
    dbg!(qy.get_y().get_value());
    let mut commitment = allocated_commitment.add(cs, &qy, jubjub_params)?;
    dbg!(commitment.get_x().get_value());
    dbg!(commitment.get_y().get_value());

    let (challenges, wrapped_proof) =
        generate_challenges(cs, &proof, &mut transcript, jubjub_params, rns_params).unwrap();

    let mut challenges_inv = Vec::with_capacity(challenges.len());

    // Compute expected commitment
    for (i, x) in challenges.iter().enumerate() {
        dbg!(x.get_field_value().map(|v| v.into_repr()));
        println!("challenges_inv: {}/{}", i, challenges.len());
        let l = wrapped_proof.l[i].clone();
        let r = wrapped_proof.r[i].clone();

        let x_inv = {
            let raw_x_inv = x.get_field_value().map(|raw_x| raw_x.inverse().unwrap());
            let x_inv = FieldElement::new_allocated_in_field(cs, raw_x_inv, rns_params)?;

            x_inv
        };
        challenges_inv.push(x_inv.clone());

        let x_bits = convert_bits_le(cs, x.clone(), None)?;
        let commitment_l = l.mul(cs, &x_bits, jubjub_params)?;
        let x_inv_bits = convert_bits_le(cs, x_inv, None)?;
        let commitment_r = r.mul(cs, &x_inv_bits, jubjub_params)?;
        commitment = commitment.add(cs, &commitment_l, jubjub_params)?.add(
            cs,
            &commitment_r,
            jubjub_params,
        )?;
        dbg!(commitment.get_x().get_value());
        dbg!(commitment.get_y().get_value());
    }

    println!("challenges_inv: {}/{}", challenges.len(), challenges.len());

    let mut current_basis = ipa_conf
        .srs
        .iter()
        .map(|v| allocate_edwards_point(cs, &Some(v.clone()), jubjub_params))
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
        current_basis = fold_points::<E, CS>(cs, &g_l, &g_r, x_inv, jubjub_params)?;
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
    let proof_a = FieldElement::new_allocated_in_field(cs, wrapped_proof.a, rns_params)?;
    let mut result1 = current_basis[0].clone(); // result1 = G[0]
    dbg!(current_basis[0].get_x().get_value());
    dbg!(current_basis[0].get_y().get_value());

    let part_2a = b[0].clone(); // part_2a = b[0]
    dbg!(b[0].get_field_value().map(|v| v.into_repr()));

    let proof_a_bits = convert_bits_le(cs, proof_a.clone(), None)?;
    result1 = result1.mul(cs, &proof_a_bits, jubjub_params)?; // result1 = a[0] * current_basis[0]
    dbg!(result1.get_x().get_value());
    dbg!(result1.get_y().get_value());

    let part_2a = {
        let (part_2a, (_, _)) = part_2a.mul(cs, proof_a)?; // part_2a = a[0] * b[0]

        part_2a
    };
    dbg!(part_2a.get_field_value().map(|v| v.into_repr()));

    let part_2a_bits = convert_bits_le(cs, part_2a, None)?;
    let result2 = qw.mul(cs, &part_2a_bits, jubjub_params)?; // result2 = a[0] * b[0] * w * Q
    dbg!(result2.get_x().get_value());
    dbg!(result2.get_y().get_value());

    let result = result1.add(cs, &result2, jubjub_params)?; // result = result1 + result2
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
