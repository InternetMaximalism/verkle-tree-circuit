use franklin_crypto::bellman::pairing::{CurveProjective, Engine};

use super::ipa::{config::IpaConfig, proof::IpaProof};

// CheckMultiProof
pub struct BatchProofCircuit<E: Engine> {
  pub ipa_conf: IpaConfig<E::G1>,
  pub proof: Option<IpaProof<E::G1>>,
  pub d: Option<E::G1>,
  pub commitments: Option<Vec<E::G1>>,
  pub ys: Option<Vec<<E::G1 as CurveProjective>::Scalar>>,
  pub zs: Option<Vec<u8>>,
}
