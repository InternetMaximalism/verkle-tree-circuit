use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use franklin_crypto::plonk::circuit::allocated_num::AllocatedNum;
use verkle_tree::ipa_fr::config::PrecomputedWeights;
use verkle_tree::ipa_fr::utils::read_field_element_le;

pub fn compute_barycentric_coefficients<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    precomputed_weights: &PrecomputedWeights<E::Fr>,
    point: &AllocatedNum<E>,
) -> anyhow::Result<Vec<AllocatedNum<E>>> {
    let domain_size = precomputed_weights.get_domain_size();

    // Compute A(x_i) * point - x_i
    let mut lagrange_evals: Vec<AllocatedNum<E>> = Vec::with_capacity(domain_size);
    let mut total_prod = AllocatedNum::<E>::one(cs);
    let barycentric_weights = precomputed_weights.get_barycentric_weights();
    for (i, barycentric_weights_i) in barycentric_weights.iter().enumerate() {
        let weight = AllocatedNum::<E>::alloc_cnst(cs, *barycentric_weights_i)?;
        let tmp_value = read_field_element_le::<E::Fr>(&i.to_le_bytes())?;
        let tmp = AllocatedNum::<E>::alloc_cnst(cs, tmp_value)?;
        let tmp = tmp.sub(cs, point)?;
        let zero = AllocatedNum::<E>::zero(cs);
        let tmp = zero.sub(cs, &tmp)?;
        total_prod = total_prod.mul(cs, &tmp)?; // total_prod *= (point - i)

        let tmp = tmp.mul(cs, &weight)?;
        lagrange_evals.push(tmp); // lagrange_evals[i] = (point - i) * weight
    }

    // TODO: Calculate the inverses of all elements together.
    for eval in lagrange_evals.iter_mut() {
        let tmp = eval.inverse(cs)?; // lagrange_evals[i] = 1 / ((point - i) * weight)
        let _ = std::mem::replace(eval, tmp);
    }

    for eval in lagrange_evals.iter_mut() {
        let tmp = eval.mul(cs, &total_prod)?; // lagrange_evals[i] = total_prod / ((point - i) * weight)
        let _ = std::mem::replace(eval, tmp);
    }

    Ok(lagrange_evals)
}
