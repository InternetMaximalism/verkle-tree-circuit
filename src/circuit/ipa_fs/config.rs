use franklin_crypto::babyjubjub::JubjubEngine;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use franklin_crypto::bellman::{Field, SynthesisError};
use franklin_crypto::plonk::circuit::bigint::field::FieldElement;
use verkle_tree::ipa_fr::config::PrecomputedWeights;
use verkle_tree::ipa_fr::utils::read_field_element_le;

pub fn compute_barycentric_coefficients<'a, E: JubjubEngine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    precomputed_weights: &PrecomputedWeights<E::Fs>,
    point: &FieldElement<'a, E, E::Fs>,
) -> Result<Vec<FieldElement<'a, E, E::Fs>>, SynthesisError> {
    let domain_size = precomputed_weights.get_domain_size();
    let rns_params = point.representation_params;

    // Compute A(x_i) * point - x_i
    let mut lagrange_evals = Vec::with_capacity(domain_size);
    let mut total_prod =
        FieldElement::<E, E::Fs>::new_allocated_in_field(cs, Some(E::Fs::one()), rns_params)?;

    let barycentric_weights = precomputed_weights.get_barycentric_weights();
    for (i, barycentric_weights_i) in barycentric_weights.iter().enumerate() {
        let weight = FieldElement::<E, E::Fs>::new_allocated_in_field(
            cs,
            Some(*barycentric_weights_i),
            rns_params,
        )?;
        let raw_tmp = read_field_element_le::<E::Fs>(&i.to_le_bytes()).unwrap();
        let tmp = FieldElement::new_allocated_in_field(cs, Some(raw_tmp), rns_params)?;
        let (tmp, _) = point.clone().sub(cs, tmp)?;
        let (r_elem, _) = total_prod.mul(cs, tmp.clone()).unwrap(); // total_prod *= (point - i)
        total_prod = r_elem;

        let (tmp_times_weight, (_, _)) = tmp.mul(cs, weight)?; // lagrange_evals[i] = (point - i) * weight
        let inv_tmp_times_weight = {
            let inv_raw = if let Some(raw) = tmp_times_weight.get_field_value() {
                let inv_raw = raw;
                inv_raw.inverse();

                Some(inv_raw)
            } else {
                None
            };
            let inv_tmp_times_weight =
                FieldElement::<E, E::Fs>::new_allocated_in_field(cs, inv_raw, rns_params)?;
            let (result, (_, _)) = tmp_times_weight.mul(cs, inv_tmp_times_weight.clone())?;
            let one = FieldElement::<E, E::Fs>::new_constant(E::Fs::one(), rns_params);
            let (assertion, (_, _)) = result.sub(cs, one)?;
            assertion.is_zero(cs)?;

            inv_tmp_times_weight
        };

        lagrange_evals.push(inv_tmp_times_weight); // lagrange_evals[i] = 1 / ((point - i) * weight)
    }

    for eval in lagrange_evals.iter_mut() {
        let (tmp, (_, _)) = eval.clone().mul(cs, total_prod.clone())?; // lagrange_evals[i] = total_prod / ((point - i) * weight)
        let _ = std::mem::replace(eval, tmp);
    }

    Ok(lagrange_evals)
}
