use franklin_crypto::babyjubjub::JubjubEngine;
use franklin_crypto::bellman::{ConstraintSystem, Field, SynthesisError};
use verkle_tree::ipa_fr::config::PrecomputedWeights;
use verkle_tree::ipa_fr::utils::read_field_element_le;

pub fn compute_barycentric_coefficients<E: JubjubEngine, CS: ConstraintSystem<E>>(
    _cs: &mut CS,
    precomputed_weights: &PrecomputedWeights<E::Fs>,
    point: &Option<E::Fs>,
) -> Result<Vec<Option<E::Fs>>, SynthesisError> {
    let domain_size = precomputed_weights.get_domain_size();

    // Compute A(x_i) * point - x_i
    let mut lagrange_evals = Vec::with_capacity(domain_size);
    let mut total_prod = E::Fs::one();
    let barycentric_weights = precomputed_weights.get_barycentric_weights();
    for i in 0..domain_size {
        if let Some(p) = point {
            let weight = barycentric_weights[i];
            let mut tmp = read_field_element_le::<E::Fs>(&i.to_le_bytes()).unwrap();
            tmp.sub_assign(p);
            tmp.negate();
            total_prod.mul_assign(&tmp); // total_prod *= (point - i)

            tmp.mul_assign(&weight); // lagrange_evals[i] = (point - i) * weight
            let tmp = tmp.inverse().unwrap(); // lagrange_evals[i] = 1 / ((point - i) * weight)
            lagrange_evals.push(Some(tmp));
        } else {
            lagrange_evals.push(None);
        }
    }

    for eval in lagrange_evals.iter_mut() {
        eval.map(|mut e| e.mul_assign(&total_prod)); // lagrange_evals[i] = total_prod / ((point - i) * weight)
    }

    Ok(lagrange_evals)
}
