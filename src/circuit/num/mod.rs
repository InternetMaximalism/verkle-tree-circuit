pub mod baby_ecc;
pub mod lookup;

// TODO: This should probably be removed and we
// should use existing helper methods on `Option`
// for mapping with an error.
/// This basically is just an extension to `Option`
/// which allows for a convenient mapping to an
/// error on `None`.
// pub trait Assignment<T> {
//     fn get(&self) -> Result<&T, SynthesisError>;
//     fn grab(self) -> Result<T, SynthesisError>;
// }

// impl<T: Clone> Assignment<T> for Option<T> {
//     fn get(&self) -> Result<&T, SynthesisError> {
//         match *self {
//             Some(ref v) => Ok(v),
//             None => Err(SynthesisError::AssignmentMissing),
//         }
//     }

//     fn grab(self) -> Result<T, SynthesisError> {
//         match self {
//             Some(v) => Ok(v),
//             None => Err(SynthesisError::AssignmentMissing),
//         }
//     }
// }
use franklin_crypto::bellman::pairing::ff::Field;

pub trait SomeField<F: Field> {
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn fma(&self, to_mul: &Self, to_add: &Self) -> Self;
    fn negate(&self) -> Self;
}

impl<F: Field> SomeField<F> for Option<F> {
    fn add(&self, other: &Self) -> Self {
        match (self, other) {
            (Some(s), Some(o)) => {
                let mut tmp = *s;
                tmp.add_assign(o);

                Some(tmp)
            }
            _ => None,
        }
    }
    fn sub(&self, other: &Self) -> Self {
        match (self, other) {
            (Some(s), Some(o)) => {
                let mut tmp = *s;
                tmp.sub_assign(o);

                Some(tmp)
            }
            _ => None,
        }
    }
    fn mul(&self, other: &Self) -> Self {
        match (self, other) {
            (Some(s), Some(o)) => {
                let mut tmp = *s;
                tmp.mul_assign(o);

                Some(tmp)
            }
            _ => None,
        }
    }
    fn fma(&self, to_mul: &Self, to_add: &Self) -> Self {
        match (self, to_mul, to_add) {
            (Some(s), Some(m), Some(a)) => {
                let mut tmp = *s;
                tmp.mul_assign(m);
                tmp.add_assign(a);

                Some(tmp)
            }
            _ => None,
        }
    }
    fn negate(&self) -> Self {
        match self {
            Some(s) => {
                let mut tmp = *s;
                tmp.negate();

                Some(tmp)
            }
            _ => None,
        }
    }
}
