use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use franklin_crypto::bellman::{Field, PrimeField};
use franklin_crypto::plonk::circuit::allocated_num::AllocatedNum;
use verkle_tree::ipa_fr::config::PrecomputedWeights;
use verkle_tree::ipa_fr::utils::read_field_element_le;

pub fn compute_barycentric_coefficients<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    precomputed_weights: &PrecomputedWeights<E::Fr>,
    point: &AllocatedNum<E>,
) -> anyhow::Result<Vec<AllocatedNum<E>>> {
    let domain_size = 2usize.pow(precomputed_weights.num_ipa_rounds as u32);

    // Compute A(x_i) * point - x_i
    let mut lagrange_evals: Vec<AllocatedNum<E>> = Vec::with_capacity(domain_size);
    let mut total_prod = AllocatedNum::<E>::one(cs);
    for i in 0..domain_size {
        let weight = AllocatedNum::<E>::alloc_cnst(cs, precomputed_weights.barycentric_weights[i])?;
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

pub fn get_inverted_element<E: Engine, F: PrimeField>(
    precomputed_weights: &PrecomputedWeights<F>,
    element: usize,
    is_neg: bool,
) -> F {
    assert!(element != 0, "cannot compute the inverse of zero");
    let mut index = element - 1;

    if is_neg {
        let midpoint = precomputed_weights.inverted_domain.len() / 2;
        index += midpoint;
    }

    precomputed_weights.inverted_domain[index]
}

pub fn get_ratio_of_weights<E: Engine, F: PrimeField>(
    precomputed_weights: &PrecomputedWeights<F>,
    numerator: usize,
    denominator: usize,
) -> F {
    let a = precomputed_weights.barycentric_weights[numerator];
    let midpoint = precomputed_weights.barycentric_weights.len() / 2;
    let b = precomputed_weights.barycentric_weights[denominator + midpoint];

    let mut result = a;
    result.mul_assign(&b);
    result
}

// Computes f(x) - f(x_i) / x - x_i where x_i is an element in the domain.
pub fn divide_on_domain<E: Engine, F: PrimeField>(
    precomputed_weights: &PrecomputedWeights<F>,
    index: usize,
    f: &[F],
) -> Vec<F> {
    let domain_size = 2usize.pow(precomputed_weights.num_ipa_rounds as u32);

    let mut quotient = vec![<F as Field>::zero(); domain_size];

    let y = f[index];

    for i in 0..domain_size {
        if i != index {
            // den = i - index
            let (abs_den, is_neg) = sub_abs(i, index); // den = i - index

            let den_inv = precomputed_weights.get_inverted_element(abs_den, is_neg);

            // compute q_i
            quotient[i] = f[i];
            quotient[i].sub_assign(&y);
            quotient[i].mul_assign(&den_inv); // quotient[i] = (f[i] - f[index]) / (i - index)

            let weight_ratio = precomputed_weights.get_ratio_of_weights(index, i);
            let mut tmp = weight_ratio;
            tmp.mul_assign(&quotient[i]); // tmp = weight_ratio * quotient[i]
            quotient[index].sub_assign(&tmp); // quotient[index] -= tmp
        }
    }

    quotient
}

// Return (|a - b|, a < b).
fn sub_abs<N: std::ops::Sub<Output = N> + std::cmp::PartialOrd>(a: N, b: N) -> (N, bool) {
    if a < b {
        (b - a, true)
    } else {
        (a - b, false)
    }
}
