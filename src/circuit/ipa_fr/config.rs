use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::{Field, PrimeField};
use verkle_tree::ipa_fr::config::{PrecomputedWeights, DOMAIN_SIZE};
use verkle_tree::ipa_fr::utils::read_field_element_le;

pub fn compute_barycentric_coefficients<E: Engine, F: PrimeField>(
    precomputed_weights: &PrecomputedWeights<F>,
    point: &F,
) -> anyhow::Result<Vec<F>> {
    // Compute A(x_i) * point - x_i
    let mut lagrange_evals: Vec<F> = Vec::with_capacity(DOMAIN_SIZE);
    let mut total_prod = F::one();
    for i in 0..DOMAIN_SIZE {
        let weight = precomputed_weights.barycentric_weights[i];
        let mut tmp = read_field_element_le::<F>(&i.to_le_bytes())?;
        tmp.sub_assign(point);
        tmp.negate();
        total_prod.mul_assign(&tmp); // total_prod *= (point - i)

        tmp.mul_assign(&weight);
        lagrange_evals.push(tmp); // lagrange_evals[i] = (point - i) * weight
    }

    // TODO: Calculate the inverses of all elements together.
    let mut lagrange_evals = {
        let mut tmp = vec![];
        for eval in lagrange_evals {
            let inverse_of_eval = eval.inverse().ok_or(anyhow::anyhow!(
                "cannot find inverse of `lagrange_evals[i]`"
            ))?; // lagrange_evals[i] = 1 / ((point - i) * weight)
            tmp.push(inverse_of_eval);
        }

        tmp
    };

    for eval in lagrange_evals.iter_mut() {
        eval.mul_assign(&total_prod); // lagrange_evals[i] = total_prod / ((point - i) * weight)
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
    let mut quotient = vec![<F as Field>::zero(); DOMAIN_SIZE];

    let y = f[index];

    for i in 0..DOMAIN_SIZE {
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
