use franklin_crypto::{
    babyjubjub::{edwards, FixedGenerators, JubjubEngine, JubjubParams},
    bellman::{
        pairing::{ff::Field, Engine},
        plonk::better_better_cs::cs::{ArithmeticTerm, ConstraintSystem, MainGateTerm},
        SynthesisError,
    },
    plonk::circuit::{
        allocated_num::{AllocatedNum, Num},
        assignment::Assignment,
        boolean::Boolean,
    },
};

use super::lookup::lookup3_xy;

#[derive(Clone)]
pub struct EdwardsPoint<E: Engine> {
    x: AllocatedNum<E>,
    y: AllocatedNum<E>,
}

/// Perform a fixed-base scalar multiplication with
/// `by` being in little-endian bit order.
pub fn fixed_base_multiplication<E, CS>(
    cs: &mut CS,
    base: FixedGenerators,
    by: &[Boolean],
    params: &E::Params,
) -> Result<EdwardsPoint<E>, SynthesisError>
where
    CS: ConstraintSystem<E>,
    E: JubjubEngine,
{
    // Represents the result of the multiplication
    let mut result = None;

    for (_, (chunk, window)) in by
        .chunks(3)
        .zip(params.circuit_generators(base).iter())
        .enumerate()
    {
        let chunk_a = chunk
            .get(0)
            .copied()
            .unwrap_or_else(|| Boolean::constant(false));
        let chunk_b = chunk
            .get(1)
            .copied()
            .unwrap_or_else(|| Boolean::constant(false));
        let chunk_c = chunk
            .get(2)
            .copied()
            .unwrap_or_else(|| Boolean::constant(false));

        let (x, y) = lookup3_xy(cs, &[chunk_a, chunk_b, chunk_c], window)?;

        let p = EdwardsPoint { x, y };

        if result.is_none() {
            result = Some(p);
        } else {
            result = Some(result.unwrap().add(cs, &p, params)?);
        }
    }

    Ok(result.get()?.clone())
}

impl<E: JubjubEngine> EdwardsPoint<E> {
    pub fn get_x(&self) -> &AllocatedNum<E> {
        &self.x
    }

    pub fn get_y(&self) -> &AllocatedNum<E> {
        &self.y
    }

    pub fn assert_not_small_order<CS>(
        &self,
        cs: &mut CS,
        params: &E::Params,
    ) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<E>,
    {
        let tmp = self.double(cs, params)?;
        let tmp = tmp.double(cs, params)?;
        let tmp = tmp.double(cs, params)?;

        // (0, -1) is a small order point, but won't ever appear here
        // because cofactor is 2^3, and we performed three doublings.
        // (0, 1) is the neutral element, so checking if x is nonzero
        // is sufficient to prevent small order points here.
        tmp.x.assert_not_zero(cs)?;

        Ok(())
    }

    pub fn inputize<CS>(&self, cs: &mut CS) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<E>,
    {
        self.x.inputize(cs)?;
        self.y.inputize(cs)?;

        Ok(())
    }

    /// This converts the point into a representation.
    pub fn repr<CS>(&self, cs: &mut CS) -> Result<Vec<Boolean>, SynthesisError>
    where
        CS: ConstraintSystem<E>,
    {
        let mut tmp = vec![];

        let x = self.x.into_bits_le(cs, None)?;

        let y = self.y.into_bits_le(cs, None)?;

        tmp.extend(y);
        tmp.push(x[0]);

        Ok(tmp)
    }

    /// This 'witnesses' a point inside the constraint system.
    /// It guarantees the point is on the curve.
    pub fn witness<Order, CS>(
        cs: &mut CS,
        p: Option<edwards::Point<E, Order>>,
        params: &E::Params,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<E>,
    {
        let p = p.map(|p| p.into_xy());

        // Allocate x
        let x = AllocatedNum::alloc(cs, || Ok(p.get()?.0))?;

        // Allocate y
        let y = AllocatedNum::alloc(cs, || Ok(p.get()?.1))?;

        Self::interpret(cs, &x, &y, params)
    }

    /// Returns `self` if condition is true, and the neutral
    /// element (0, 1) otherwise.
    pub fn conditionally_select<CS>(
        &self,
        cs: &mut CS,
        condition: &Boolean,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<E>,
    {
        // Compute x' = self.x if condition, and 0 otherwise
        // let x_prime = AllocatedNum::alloc(cs, || {
        //     if *condition.get_value().get()? {
        //         Ok(*self.x.get_value().get()?)
        //     } else {
        //         Ok(E::Fr::zero())
        //     }
        // })?;

        // condition * x = x'
        // if condition is 0, x' must be 0
        // if condition is 1, x' must be x
        // cs.enforce(
        //     || "x' computation",
        //     |lc| lc + self.x.get_variable(),
        //     |_| condition.lc(E::Fr::one()),
        //     |lc| lc + x_prime.get_variable(),
        // );
        let zero = AllocatedNum::zero(cs);
        let x_prime = AllocatedNum::conditionally_select(cs, &self.x, &zero, condition)?;

        // Compute y' = self.y if condition, and 1 otherwise
        // let y_prime = AllocatedNum::alloc(cs, || {
        //     if *condition.get_value().get()? {
        //         Ok(*self.y.get_value().get()?)
        //     } else {
        //         Ok(E::Fr::one())
        //     }
        // })?;

        // condition * y = y' - (1 - condition)
        // if condition is 0, y' must be 1
        // if condition is 1, y' must be y
        // cs.enforce(
        //     || "y' computation",
        //     |lc| lc + self.y.get_variable(),
        //     |_| condition.lc(E::Fr::one()),
        //     |lc| lc + y_prime.get_variable() - &condition.not().lc(E::Fr::one()),
        // );
        let one = AllocatedNum::one(cs);
        let y_prime = AllocatedNum::conditionally_select(cs, &self.y, &one, condition)?;

        Ok(EdwardsPoint {
            x: x_prime,
            y: y_prime,
        })
    }

    /// Performs a scalar multiplication of this twisted Edwards
    /// point by a scalar represented as a sequence of booleans
    /// in little-endian bit order.
    pub fn mul<CS>(
        &self,
        cs: &mut CS,
        by: &[Boolean],
        params: &E::Params,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<E>,
    {
        // Represents the current "magnitude" of the base
        // that we're operating over. Starts at self,
        // then 2*self, then 4*self, ...
        let mut curbase = None;

        // Represents the result of the multiplication
        let mut result = None;

        for (_, bit) in by.iter().enumerate() {
            if curbase.is_none() {
                curbase = Some(self.clone());
            } else {
                // Double the previous value
                curbase = Some(curbase.unwrap().double(cs, params)?);
            }

            // Represents the select base. If the bit for this magnitude
            // is true, this will return `curbase`. Otherwise it will
            // return the neutral element, which will have no effect on
            // the result.
            let thisbase = curbase.as_ref().unwrap().conditionally_select(cs, bit)?;

            if result.is_none() {
                result = Some(thisbase);
            } else {
                result = Some(result.unwrap().add(cs, &thisbase, params)?);
            }
        }

        Ok(result.get()?.clone())
    }

    pub fn interpret<CS>(
        cs: &mut CS,
        x: &AllocatedNum<E>,
        y: &AllocatedNum<E>,
        params: &E::Params,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<E>,
    {
        // a*x^2 + y^2 = 1 + dx^2y^2

        let x2 = x.square(cs)?;
        let y2 = y.square(cs)?;
        let x2y2 = x2.mul(cs, &y2)?;
        let dx2y2 = x2y2.mul_constant(cs, *params.edwards_d())?;
        let ax2 = x2.mul_constant(cs, *params.edwards_a())?;

        // cs.enforce(
        //     || "on curve check",
        //     |lc| lc + (*params.edwards_a(), x2.get_variable()) + y2.get_variable(),
        //     |lc| lc + one,
        //     |lc| lc + one + (*params.edwards_d(), x2y2.get_variable()),
        // );
        {
            let one = cs.get_explicit_one()?;
            let ax2_term = ArithmeticTerm::<E>::from_variable(ax2.get_variable());
            let y2_term = ArithmeticTerm::from_variable(y2.get_variable());
            let one_term = ArithmeticTerm::from_variable(one);
            let dx2y2_term = ArithmeticTerm::from_variable(dx2y2.get_variable());

            let mut term = MainGateTerm::new();
            term.add_assign(ax2_term);
            term.add_assign(y2_term);
            term.sub_assign(one_term);
            term.sub_assign(dx2y2_term);
            cs.allocate_main_gate(term)?;
        }

        Ok(EdwardsPoint { x: *x, y: *y })
    }

    pub fn double<CS>(&self, cs: &mut CS, params: &E::Params) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<E>,
    {
        // Compute A = x1 * y1
        let a = self.x.mul(cs, &self.y)?;

        // Compute T = x1 * x1
        let t = self.x.mul(cs, &self.x)?;

        // Compute U = y1 * y1
        let u = self.y.mul(cs, &self.y)?;

        // Compute C = d*A*A
        let c = AllocatedNum::alloc(cs, || {
            let mut t0 = *a.get_value().get()?;
            t0.square();
            t0.mul_assign(params.edwards_d());

            Ok(t0)
        })?;

        // cs.enforce(
        //     || "C computation",
        //     |lc| lc + (*params.edwards_d(), a.get_variable()),
        //     |lc| lc + a.get_variable(),
        //     |lc| lc + c.get_variable(),
        // );
        {
            let mut self_daa_term = ArithmeticTerm::from_variable(a.get_variable());
            let c_term = ArithmeticTerm::from_variable(c.get_variable());
            self_daa_term = self_daa_term.mul_by_variable(a.get_variable());
            self_daa_term.scale(params.edwards_d());

            let mut term = MainGateTerm::new();
            term.add_assign(self_daa_term);
            term.sub_assign(c_term);
            cs.allocate_main_gate(term)?;
        }

        // Compute x3 = (2.A) / (1 + C)
        let x3 = AllocatedNum::alloc(cs, || {
            let mut t0 = *a.get_value().get()?;
            t0.double();

            let mut t1 = E::Fr::one();
            t1.add_assign(c.get_value().get()?);

            match t1.inverse() {
                Some(t1) => {
                    t0.mul_assign(&t1);

                    Ok(t0)
                }
                None => Err(SynthesisError::DivisionByZero),
            }
        })?;

        // cs.enforce(
        //     || "x3 computation",
        //     |lc| lc + one + c.get_variable(),
        //     |lc| lc + x3.get_variable(),
        //     |lc| lc + a.get_variable() + a.get_variable(),
        // );
        let one = cs.get_explicit_one()?;
        {
            let mut term1 = MainGateTerm::new();
            let c_term = ArithmeticTerm::from_variable(c.get_variable());
            let one_plus_c = c.add_constant(cs, E::Fr::one())?.get_variable();
            let one_plus_c_term = ArithmeticTerm::from_variable(one_plus_c);
            let one_term = ArithmeticTerm::from_variable(one);
            term1.add_assign(c_term);
            term1.add_assign(one_term);
            term1.sub_assign(one_plus_c_term);
            cs.allocate_main_gate(term1)?;

            let x3_term = ArithmeticTerm::from_variable(x3.get_variable());
            let one_plus_c_times_x3_term = x3_term.mul_by_variable(one_plus_c);

            let mut term3 = MainGateTerm::new();
            let a_term = ArithmeticTerm::from_variable(a.get_variable());
            let a_plus_a_term = ArithmeticTerm::from_variable(a.add(cs, &a)?.get_variable());
            term3.add_assign(a_term.clone());
            term3.add_assign(a_term);
            term3.sub_assign(a_plus_a_term.clone());
            cs.allocate_main_gate(term3)?;

            let mut term = MainGateTerm::new();
            term.add_assign(one_plus_c_times_x3_term);
            term.sub_assign(a_plus_a_term);
            cs.allocate_main_gate(term)?;
        }

        // Compute y3 = (U - edwards_a.T) / (1 - C)
        let y3 = AllocatedNum::alloc(cs, || {
            let mut t0 = *u.get_value().get()?;

            let mut u0 = *t.get_value().get()?;
            u0.mul_assign(params.edwards_a());

            t0.sub_assign(&u0);

            let mut t1 = E::Fr::one();
            t1.sub_assign(c.get_value().get()?);

            match t1.inverse() {
                Some(t1) => {
                    t0.mul_assign(&t1);

                    Ok(t0)
                }
                None => Err(SynthesisError::DivisionByZero),
            }
        })?;

        // y3 = (U - edwards_a.T) / (1 - C)
        // cs.enforce(
        //     || "y3 computation",
        //     |lc| lc + one - c.get_variable(),
        //     |lc| lc + y3.get_variable(),
        //     |lc| lc + u.get_variable() - (*params.edwards_a(), t.get_variable()),
        // );
        {
            let mut term1 = MainGateTerm::new();
            let c_term = ArithmeticTerm::from_variable(c.get_variable());
            let zero = AllocatedNum::zero(cs);
            let neg_c = zero.sub(cs, &c)?;
            let one_minus_c = neg_c.add_constant(cs, E::Fr::one())?.get_variable();
            let one_minus_c_term = ArithmeticTerm::from_variable(one_minus_c);
            let one_term = ArithmeticTerm::from_variable(one);
            term1.add_assign(one_term);
            term1.sub_assign(c_term);
            term1.sub_assign(one_minus_c_term);
            cs.allocate_main_gate(term1)?;

            let y3_term = ArithmeticTerm::from_variable(y3.get_variable());
            let one_minus_c_times_y3_term = y3_term.mul_by_variable(one_minus_c);

            let mut term3 = MainGateTerm::new();
            let a_times_t = t.mul_constant(cs, *params.edwards_a())?;
            let mut a_times_t_term = ArithmeticTerm::from_variable(t.get_variable());
            a_times_t_term.scale(params.edwards_a());
            let u_term = ArithmeticTerm::from_variable(u.get_variable());
            let u_minus_at_term =
                ArithmeticTerm::from_variable(u.sub(cs, &a_times_t)?.get_variable());
            term3.add_assign(u_term);
            term3.sub_assign(a_times_t_term);
            term3.sub_assign(u_minus_at_term.clone());
            cs.allocate_main_gate(term3)?;

            let mut term = MainGateTerm::new();
            term.add_assign(one_minus_c_times_y3_term);
            term.sub_assign(u_minus_at_term);
            cs.allocate_main_gate(term)?;
        }

        Ok(EdwardsPoint { x: x3, y: y3 })
    }

    /// Perform addition between any two points
    pub fn add<CS>(
        &self,
        cs: &mut CS,
        other: &Self,
        params: &E::Params,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<E>,
    {
        // Compute A = y2 * x1
        let a = other.y.mul(cs, &self.x)?;

        // Compute B = x2 * y1
        let b = other.x.mul(cs, &self.y)?;

        // Compute T = (-a * x1 + y1) * (x2 + y2)
        let t = AllocatedNum::alloc(cs, || {
            let mut t0 = *self.x.get_value().get()?;
            t0.mul_assign(params.edwards_a());
            t0.negate();
            t0.add_assign(self.y.get_value().get()?);

            let mut t1 = *other.x.get_value().get()?;
            t1.add_assign(other.y.get_value().get()?);

            t0.mul_assign(&t1);

            Ok(t0)
        })?;

        // cs.enforce(
        //     || "T computation",
        //     |lc| lc - (*params.edwards_a(), self.x.get_variable()) + self.y.get_variable(),
        //     |lc| lc + other.x.get_variable() + other.y.get_variable(),
        //     |lc| lc + t.get_variable(),
        // );
        let self_x_a = self.x.mul_constant(cs, *params.edwards_a())?;
        let left = self.y.sub(cs, &self_x_a)?;
        let right = other.x.add(cs, &other.y)?;
        let output = left.mul(cs, &right)?;
        {
            let self_x_a_term = ArithmeticTerm::from_variable(self_x_a.get_variable());
            let self_y_term = ArithmeticTerm::from_variable(self.y.get_variable());
            let left_term = ArithmeticTerm::from_variable(left.get_variable());

            let mut term1 = MainGateTerm::new();
            term1.sub_assign(self_x_a_term);
            term1.add_assign(self_y_term);
            term1.sub_assign(left_term);
            cs.allocate_main_gate(term1)?;

            let other_x_term = ArithmeticTerm::from_variable(other.x.get_variable());
            let other_y_term = ArithmeticTerm::from_variable(other.y.get_variable());
            let right_term = ArithmeticTerm::from_variable(right.get_variable());

            let mut term2 = MainGateTerm::new();
            term2.add_assign(other_x_term);
            term2.add_assign(other_y_term);
            term2.sub_assign(right_term);
            cs.allocate_main_gate(term2)?;

            let t_term = ArithmeticTerm::from_variable(t.get_variable());
            let output_term = ArithmeticTerm::from_variable(output.get_variable());

            let mut term3 = MainGateTerm::new();
            term3.add_assign(t_term);
            term3.sub_assign(output_term);
            cs.allocate_main_gate(term3)?;
        }

        // Compute C = d*A*B
        let c = AllocatedNum::alloc(cs, || {
            let mut t0 = *a.get_value().get()?;
            t0.mul_assign(b.get_value().get()?);
            t0.mul_assign(params.edwards_d());

            Ok(t0)
        })?;

        // cs.enforce(
        //     || "C computation",
        //     |lc| lc + (*params.edwards_d(), a.get_variable()),
        //     |lc| lc + b.get_variable(),
        //     |lc| lc + c.get_variable(),
        // );
        {
            let mut term = MainGateTerm::new();
            let mut self_dab_term = ArithmeticTerm::from_variable(a.get_variable());
            let c_term = ArithmeticTerm::from_variable(c.get_variable());
            self_dab_term = self_dab_term.mul_by_variable(b.get_variable());
            self_dab_term.scale(params.edwards_d());
            term.add_assign(self_dab_term);
            term.sub_assign(c_term);
            cs.allocate_main_gate(term)?;
        }

        // Compute x3 = (A + B) / (1 + C)
        let x3 = AllocatedNum::alloc(cs, || {
            let mut t0 = *a.get_value().get()?;
            t0.add_assign(b.get_value().get()?);

            let mut t1 = E::Fr::one();
            t1.add_assign(c.get_value().get()?);

            match t1.inverse() {
                Some(t1) => {
                    t0.mul_assign(&t1);

                    Ok(t0)
                }
                None => Err(SynthesisError::DivisionByZero),
            }
        })?;

        // cs.enforce(
        //     || "x3 computation",
        //     |lc| lc + one + c.get_variable(),
        //     |lc| lc + x3.get_variable(),
        //     |lc| lc + a.get_variable() + b.get_variable(),
        // );
        let one = cs.get_explicit_one()?;
        {
            let mut term1 = MainGateTerm::new();
            let c_term = ArithmeticTerm::from_variable(c.get_variable());
            let one_plus_c = c.add_constant(cs, E::Fr::one())?.get_variable();
            let one_plus_c_term = ArithmeticTerm::from_variable(one_plus_c);
            let one_term = ArithmeticTerm::from_variable(one);
            term1.add_assign(c_term);
            term1.add_assign(one_term);
            term1.sub_assign(one_plus_c_term);
            cs.allocate_main_gate(term1)?;

            let x3_term = ArithmeticTerm::from_variable(x3.get_variable());
            let one_plus_c_times_x3_term = x3_term.mul_by_variable(one_plus_c);

            let mut term3 = MainGateTerm::new();
            let a_term = ArithmeticTerm::from_variable(a.get_variable());
            let b_term = ArithmeticTerm::from_variable(b.get_variable());
            let a_plus_b_term = ArithmeticTerm::from_variable(a.add(cs, &b)?.get_variable());
            term3.add_assign(a_term);
            term3.add_assign(b_term);
            term3.sub_assign(a_plus_b_term.clone());
            cs.allocate_main_gate(term3)?;

            let mut term = MainGateTerm::new();
            term.add_assign(one_plus_c_times_x3_term);
            term.sub_assign(a_plus_b_term);
            cs.allocate_main_gate(term)?;
        }

        // Compute y3 = (T + edwards.a * A - B) / (1 - C)
        let y3 = AllocatedNum::alloc(cs, || {
            let mut a0 = *a.get_value().get()?;
            a0.mul_assign(params.edwards_a());

            let mut t0 = *t.get_value().get()?;
            t0.add_assign(&a0);
            t0.sub_assign(b.get_value().get()?);

            let mut t1 = E::Fr::one();
            t1.sub_assign(c.get_value().get()?);

            match t1.inverse() {
                Some(t1) => {
                    t0.mul_assign(&t1);

                    Ok(t0)
                }
                None => Err(SynthesisError::DivisionByZero),
            }
        })?;

        // cs.enforce(
        //     || "y3 computation",
        //     |lc| lc + one - c.get_variable(),
        //     |lc| lc + y3.get_variable(),
        //     |lc| lc + t.get_variable() + (*params.edwards_a(), a.get_variable()) - b.get_variable(),
        // );
        let zero = AllocatedNum::zero(cs);
        let neg_c = zero.sub(cs, &c)?;
        let one_minus_c = neg_c.add_constant(cs, E::Fr::one())?;
        let one_minus_c_times_y3 = y3.mul(cs, &one_minus_c)?;
        let aa = a.mul_constant(cs, *params.edwards_a())?;
        let output = t.add(cs, &aa)?.sub(cs, &b)?;
        {
            // let c_term = ArithmeticTerm::from_variable(c.get_variable());
            // let one_minus_c_term = ArithmeticTerm::from_variable(one_minus_c.get_variable());
            // let one_term = ArithmeticTerm::from_variable(one);

            // let mut term1 = MainGateTerm::new();
            // term1.add_assign(one_term);
            // term1.sub_assign(c_term);
            // term1.sub_assign(one_minus_c_term);
            // cs.allocate_main_gate(term1)?;

            // let y3_term = ArithmeticTerm::from_variable(y3.get_variable());
            let one_minus_c_times_y3_term =
                ArithmeticTerm::from_variable(one_minus_c_times_y3.get_variable());

            // let mut term3 = MainGateTerm::new();
            // let t_term = ArithmeticTerm::from_variable(t.get_variable());
            // let aa = a.mul_constant(cs, *params.edwards_a())?;
            // let mut aa_term = ArithmeticTerm::from_variable(a.get_variable());
            // aa_term.scale(params.edwards_a());
            // let b_term = ArithmeticTerm::from_variable(b.get_variable());
            let t_plus_aa_minus_b_term = ArithmeticTerm::from_variable(output.get_variable());
            // let t_plus_aa_minus_b_term =
            //     ArithmeticTerm::from_variable(t.add(cs, &aa)?.add(cs, &b)?.get_variable());
            // term3.add_assign(t_term);
            // term3.add_assign(aa_term);
            // term3.sub_assign(b_term);
            // term3.sub_assign(t_plus_aa_minus_b_term.clone());
            // cs.allocate_main_gate(term3)?;

            let mut term = MainGateTerm::new();
            term.add_assign(one_minus_c_times_y3_term);
            term.sub_assign(t_plus_aa_minus_b_term);
            cs.allocate_main_gate(term)?;
        }

        Ok(EdwardsPoint { x: x3, y: y3 })
    }
}

pub struct MontgomeryPoint<E: Engine> {
    x: Num<E>,
    y: Num<E>,
}

impl<E: JubjubEngine> MontgomeryPoint<E> {
    /// Converts an element in the prime order subgroup into
    /// a point in the birationally equivalent twisted
    /// Edwards curve.
    pub fn into_edwards<CS>(
        &self,
        cs: &mut CS,
        params: &E::Params,
    ) -> Result<EdwardsPoint<E>, SynthesisError>
    where
        CS: ConstraintSystem<E>,
    {
        // Compute u = (scale*x) / y
        let u = AllocatedNum::alloc(cs, || {
            let mut t0 = *self.x.get_value().get()?;
            t0.mul_assign(params.scale());

            match self.y.get_value().get()?.inverse() {
                Some(invy) => {
                    t0.mul_assign(&invy);

                    Ok(t0)
                }
                None => Err(SynthesisError::DivisionByZero),
            }
        })?;

        // cs.enforce(
        //     || "u computation",
        //     |lc| lc + &self.y.lc(E::Fr::one()),
        //     |lc| lc + u.get_variable(),
        //     |lc| lc + &self.x.lc(*params.scale()),
        // );
        {
            let y_term = ArithmeticTerm::from_variable(self.y.get_variable().get_variable());
            let y_times_u_term = y_term.mul_by_variable(u.get_variable());
            let mut x_term = ArithmeticTerm::from_variable(self.x.get_variable().get_variable());
            x_term.scale(params.scale());

            let mut term = MainGateTerm::new();
            term.add_assign(y_times_u_term);
            term.sub_assign(x_term);
            cs.allocate_main_gate(term)?;
        }

        // Compute v = (x - 1) / (x + 1)
        let v = AllocatedNum::alloc(cs, || {
            let mut t0 = *self.x.get_value().get()?;
            let mut t1 = t0;
            t0.sub_assign(&E::Fr::one());
            t1.add_assign(&E::Fr::one());

            match t1.inverse() {
                Some(t1) => {
                    t0.mul_assign(&t1);

                    Ok(t0)
                }
                None => Err(SynthesisError::DivisionByZero),
            }
        })?;

        let one = AllocatedNum::one(cs);
        // cs.enforce(
        //     || "v computation",
        //     |lc| lc + &self.x.lc(E::Fr::one()) + one,
        //     |lc| lc + v.get_variable(),
        //     |lc| lc + &self.x.lc(E::Fr::one()) - one,
        // );
        {
            let x = self.x.get_variable();
            let x_term = ArithmeticTerm::from_variable(x.get_variable());
            let one_term = ArithmeticTerm::from_variable(one.get_variable());
            let x_plus_one = x.add(cs, &one)?;
            let x_plus_one_term = ArithmeticTerm::from_variable(x_plus_one.get_variable());

            let mut term1 = MainGateTerm::new();
            term1.add_assign(x_term.clone());
            term1.add_assign(one_term.clone());
            term1.sub_assign(x_plus_one_term.clone());
            cs.allocate_main_gate(term1)?;

            let mut term2 = MainGateTerm::new();
            term2.add_assign(x_plus_one_term.mul_by_variable(v.get_variable()));
            term2.sub_assign(x_term);
            term2.add_assign(one_term);
            cs.allocate_main_gate(term2)?;
        }

        Ok(EdwardsPoint { x: u, y: v })
    }

    /// Interprets an (x, y) pair as a point
    /// in Montgomery, does not check that it's
    /// on the curve. Useful for constants and
    /// window table lookups.
    pub fn interpret_unchecked(x: Num<E>, y: Num<E>) -> Self {
        MontgomeryPoint { x, y }
    }

    /// Performs an affine point addition, not defined for
    /// coincident points.
    pub fn add<CS>(
        &self,
        cs: &mut CS,
        other: &Self,
        params: &E::Params,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<E>,
    {
        // Compute lambda = (y' - y) / (x' - x)
        let lambda = AllocatedNum::alloc(cs, || {
            let mut n = *other.y.get_value().get()?;
            n.sub_assign(self.y.get_value().get()?);

            let mut d = *other.x.get_value().get()?;
            d.sub_assign(self.x.get_value().get()?);

            match d.inverse() {
                Some(d) => {
                    n.mul_assign(&d);
                    Ok(n)
                }
                None => Err(SynthesisError::DivisionByZero),
            }
        })?;

        // cs.enforce(
        //     || "evaluate lambda",
        //     |lc| lc + &other.x.lc(E::Fr::one()) - &self.x.lc(E::Fr::one()),
        //     |lc| lc + lambda.get_variable(),
        //     |lc| lc + &other.y.lc(E::Fr::one()) - &self.y.lc(E::Fr::one()),
        // );
        {
            let x_term = ArithmeticTerm::from_variable(self.x.get_variable().get_variable());
            let x_prime_term = ArithmeticTerm::from_variable(other.x.get_variable().get_variable());
            let x_prime_minus_x_term = ArithmeticTerm::from_variable(
                other.x.sub(cs, &self.x)?.get_variable().get_variable(),
            );

            let mut term1 = MainGateTerm::new();
            term1.add_assign(x_prime_term);
            term1.sub_assign(x_term);
            term1.sub_assign(x_prime_minus_x_term.clone());
            cs.allocate_main_gate(term1)?;

            let output = x_prime_minus_x_term.mul_by_variable(lambda.get_variable());
            let y_prime_term = ArithmeticTerm::from_variable(other.y.get_variable().get_variable());
            let y_term = ArithmeticTerm::from_variable(self.y.get_variable().get_variable());
            let mut term2 = MainGateTerm::new();
            term2.add_assign(y_prime_term);
            term2.sub_assign(y_term);
            term2.sub_assign(output);
            cs.allocate_main_gate(term2)?;
        }

        // Compute x'' = lambda^2 - A - x - x'
        let xprime = AllocatedNum::alloc(cs, || {
            let mut t0 = *lambda.get_value().get()?;
            t0.square();
            t0.sub_assign(params.montgomery_a());
            t0.sub_assign(self.x.get_value().get()?);
            t0.sub_assign(other.x.get_value().get()?);

            Ok(t0)
        })?;

        // (lambda) * (lambda) = (A + x + x' + x'')
        // cs.enforce(
        //     || "evaluate xprime",
        //     |lc| lc + lambda.get_variable(),
        //     |lc| lc + lambda.get_variable(),
        //     |lc| {
        //         lc + (*params.montgomery_a(), one)
        //             + &self.x.lc(E::Fr::one())
        //             + &other.x.lc(E::Fr::one())
        //             + xprime.get_variable()
        //     },
        // );
        {
            let lambda2 = lambda.mul(cs, &lambda)?;
            let lambda2_term = ArithmeticTerm::from_variable(lambda2.get_variable());
            let x_term = ArithmeticTerm::from_variable(self.x.get_variable().get_variable());
            let x_prime_term = ArithmeticTerm::from_variable(other.x.get_variable().get_variable());
            let x_double_prime = ArithmeticTerm::from_variable(xprime.get_variable());

            let mut term = MainGateTerm::new();
            term.add_assign(lambda2_term);
            term.sub_assign(x_term);
            term.sub_assign(x_prime_term);
            term.sub_assign(x_double_prime);
            cs.allocate_main_gate(term)?;
        }

        // Compute y' = -(y + lambda(x' - x))
        let yprime = AllocatedNum::alloc(cs, || {
            let mut t0 = *xprime.get_value().get()?;
            t0.sub_assign(self.x.get_value().get()?);
            t0.mul_assign(lambda.get_value().get()?);
            t0.add_assign(self.y.get_value().get()?);
            t0.negate();

            Ok(t0)
        })?;

        // y' + y = lambda(x - x')
        // cs.enforce(
        //     || "evaluate yprime",
        //     |lc| lc + &self.x.lc(E::Fr::one()) - xprime.get_variable(),
        //     |lc| lc + lambda.get_variable(),
        //     |lc| lc + yprime.get_variable() + &self.y.lc(E::Fr::one()),
        // );
        {
            let x_term = ArithmeticTerm::from_variable(self.x.get_variable().get_variable());
            let x_prime_term = ArithmeticTerm::from_variable(xprime.get_variable());
            let x_minus_x_prime = self.x.get_variable().add(cs, &xprime)?;
            let x_minus_x_prime_term =
                ArithmeticTerm::from_variable(x_minus_x_prime.get_variable());
            let y_prime_term = ArithmeticTerm::from_variable(yprime.get_variable());
            let y_term = ArithmeticTerm::from_variable(self.y.get_variable().get_variable());

            let mut term1 = MainGateTerm::new();
            term1.add_assign(x_term);
            term1.sub_assign(x_prime_term);
            term1.sub_assign(x_minus_x_prime_term.clone());
            cs.allocate_main_gate(term1)?;

            let mut term2 = MainGateTerm::new();
            let output = x_minus_x_prime_term.mul_by_variable(lambda.get_variable());
            term2.add_assign(y_prime_term);
            term2.add_assign(y_term);
            term2.sub_assign(output);
            cs.allocate_main_gate(term2)?;
        }

        Ok(MontgomeryPoint {
            x: Num::Variable(xprime),
            y: Num::Variable(yprime),
        })
    }
}

// #[cfg(test)]
// mod test {
//     use franklin_crypto::{
//         babyjubjub::{edwards, fs::Fs, montgomery, FixedGenerators, JubjubBn256, JubjubParams},
//         bellman::{
//             pairing::bn256::{Bn256, Fr},
//             pairing::ff::{BitIterator, Field, PrimeField},
//             ConstraintSystem,
//         },
//         circuit::{
//             boolean::{AllocatedBit, Boolean},
//             test::*,
//         },
//     };
//     use rand::{Rand, Rng, SeedableRng, XorShiftRng};

//     use super::{fixed_base_multiplication, AllocatedNum, EdwardsPoint, MontgomeryPoint};

//     #[test]
//     fn test_into_edwards() {
//         let params = &JubjubBn256::new();
//         let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

//         for _ in 0..100 {
//             let mut cs = TestConstraintSystem::<Bn256>::new();

//             let p = montgomery::Point::<Bn256, _>::rand(rng, params);
//             let (u, v) = edwards::Point::from_montgomery(&p, params).into_xy();
//             let (x, y) = p.into_xy().unwrap();

//             let numx = AllocatedNum::alloc(cs.namespace(|| "mont x"), || Ok(x)).unwrap();
//             let numy = AllocatedNum::alloc(cs.namespace(|| "mont y"), || Ok(y)).unwrap();

//             let p = MontgomeryPoint::interpret_unchecked(numx.into(), numy.into());

//             let q = p.into_edwards(&mut cs, params).unwrap();

//             assert!(cs.is_satisfied());
//             assert!(q.x.get_value().unwrap() == u);
//             assert!(q.y.get_value().unwrap() == v);

//             cs.set("u/num", rng.gen());
//             assert_eq!(cs.which_is_unsatisfied().unwrap(), "u computation");
//             cs.set("u/num", u);
//             assert!(cs.is_satisfied());

//             cs.set("v/num", rng.gen());
//             assert_eq!(cs.which_is_unsatisfied().unwrap(), "v computation");
//             cs.set("v/num", v);
//             assert!(cs.is_satisfied());
//         }
//     }

//     #[test]
//     fn test_interpret() {
//         let params = &JubjubBn256::new();
//         let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

//         for _ in 0..100 {
//             let p = edwards::Point::<Bn256, _>::rand(rng, &params);

//             let mut cs = TestConstraintSystem::<Bn256>::new();
//             let q = EdwardsPoint::witness(&mut cs, Some(p.clone()), &params).unwrap();

//             let p = p.into_xy();

//             assert!(cs.is_satisfied());
//             assert_eq!(q.x.get_value().unwrap(), p.0);
//             assert_eq!(q.y.get_value().unwrap(), p.1);
//         }

//         for _ in 0..100 {
//             let p = edwards::Point::<Bn256, _>::rand(rng, &params);
//             let (x, y) = p.into_xy();

//             let mut cs = TestConstraintSystem::<Bn256>::new();
//             let numx = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(x)).unwrap();
//             let numy = AllocatedNum::alloc(cs.namespace(|| "y"), || Ok(y)).unwrap();

//             let p = EdwardsPoint::interpret(&mut cs, &numx, &numy, &params).unwrap();

//             assert!(cs.is_satisfied());
//             assert_eq!(p.x.get_value().unwrap(), x);
//             assert_eq!(p.y.get_value().unwrap(), y);
//         }

//         // Random (x, y) are unlikely to be on the curve.
//         for _ in 0..100 {
//             let x = rng.gen();
//             let y = rng.gen();

//             let mut cs = TestConstraintSystem::<Bn256>::new();
//             let numx = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(x)).unwrap();
//             let numy = AllocatedNum::alloc(cs.namespace(|| "y"), || Ok(y)).unwrap();

//             EdwardsPoint::interpret(&mut cs, &numx, &numy, &params).unwrap();

//             assert_eq!(cs.which_is_unsatisfied().unwrap(), "on curve check");
//         }
//     }

//     #[test]
//     fn test_edwards_fixed_base_multiplication() {
//         let params = &JubjubBn256::new();
//         let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

//         for _ in 0..100 {
//             let mut cs = TestConstraintSystem::<Bn256>::new();

//             let p = params.generator(FixedGenerators::NoteCommitmentRandomness);
//             let s = Fs::rand(rng);
//             let q = p.mul(s, params);
//             let (x1, y1) = q.into_xy();

//             let mut s_bits = BitIterator::new(s.into_repr()).collect::<Vec<_>>();
//             s_bits.reverse();
//             s_bits.truncate(Fs::NUM_BITS as usize);

//             let s_bits = s_bits
//                 .into_iter()
//                 .enumerate()
//                 .map(|(i, b)| {
//                     AllocatedBit::alloc(cs.namespace(|| format!("scalar bit {}", i)), Some(b))
//                         .unwrap()
//                 })
//                 .map(|v| Boolean::from(v))
//                 .collect::<Vec<_>>();

//             let q = fixed_base_multiplication(
//                 cs.namespace(|| "multiplication"),
//                 FixedGenerators::NoteCommitmentRandomness,
//                 &s_bits,
//                 params,
//             )
//             .unwrap();

//             assert_eq!(q.x.get_value().unwrap(), x1);
//             assert_eq!(q.y.get_value().unwrap(), y1);
//         }
//     }

//     #[test]
//     fn test_edwards_multiplication() {
//         let params = &JubjubBn256::new();
//         let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

//         for _ in 0..100 {
//             let mut cs = TestConstraintSystem::<Bn256>::new();

//             let p = edwards::Point::<Bn256, _>::rand(rng, params);
//             let s = Fs::rand(rng);
//             let q = p.mul(s, params);

//             let (x0, y0) = p.into_xy();
//             let (x1, y1) = q.into_xy();

//             let num_x0 = AllocatedNum::alloc(cs.namespace(|| "x0"), || Ok(x0)).unwrap();
//             let num_y0 = AllocatedNum::alloc(cs.namespace(|| "y0"), || Ok(y0)).unwrap();

//             let p = EdwardsPoint {
//                 x: num_x0,
//                 y: num_y0,
//             };

//             let mut s_bits = BitIterator::new(s.into_repr()).collect::<Vec<_>>();
//             s_bits.reverse();
//             s_bits.truncate(Fs::NUM_BITS as usize);

//             let s_bits = s_bits
//                 .into_iter()
//                 .enumerate()
//                 .map(|(i, b)| {
//                     AllocatedBit::alloc(cs.namespace(|| format!("scalar bit {}", i)), Some(b))
//                         .unwrap()
//                 })
//                 .map(|v| Boolean::from(v))
//                 .collect::<Vec<_>>();

//             let q = p
//                 .mul(cs.namespace(|| "scalar mul"), &s_bits, params)
//                 .unwrap();

//             assert!(cs.is_satisfied());

//             assert_eq!(q.x.get_value().unwrap(), x1);

//             assert_eq!(q.y.get_value().unwrap(), y1);
//         }
//     }

//     #[test]
//     fn test_conditionally_select() {
//         let params = &JubjubBn256::new();
//         let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

//         for _ in 0..1000 {
//             let mut cs = TestConstraintSystem::<Bn256>::new();

//             let p = edwards::Point::<Bn256, _>::rand(rng, params);

//             let (x0, y0) = p.into_xy();

//             let num_x0 = AllocatedNum::alloc(cs.namespace(|| "x0"), || Ok(x0)).unwrap();
//             let num_y0 = AllocatedNum::alloc(cs.namespace(|| "y0"), || Ok(y0)).unwrap();

//             let p = EdwardsPoint {
//                 x: num_x0,
//                 y: num_y0,
//             };

//             let mut should_we_select = rng.gen();

//             // Conditionally allocate
//             let mut b = if rng.gen() {
//                 Boolean::from(
//                     AllocatedBit::alloc(cs.namespace(|| "condition"), Some(should_we_select))
//                         .unwrap(),
//                 )
//             } else {
//                 Boolean::constant(should_we_select)
//             };

//             // Conditionally negate
//             if rng.gen() {
//                 b = b.not();
//                 should_we_select = !should_we_select;
//             }

//             let q = p
//                 .conditionally_select(cs.namespace(|| "select"), &b)
//                 .unwrap();

//             assert!(cs.is_satisfied());

//             if should_we_select {
//                 assert_eq!(q.x.get_value().unwrap(), x0);
//                 assert_eq!(q.y.get_value().unwrap(), y0);

//                 cs.set("select/y'/num", Fr::one());
//                 assert_eq!(cs.which_is_unsatisfied().unwrap(), "select/y' computation");
//                 cs.set("select/x'/num", Fr::zero());
//                 assert_eq!(cs.which_is_unsatisfied().unwrap(), "select/x' computation");
//             } else {
//                 assert_eq!(q.x.get_value().unwrap(), Fr::zero());
//                 assert_eq!(q.y.get_value().unwrap(), Fr::one());

//                 cs.set("select/y'/num", x0);
//                 assert_eq!(cs.which_is_unsatisfied().unwrap(), "select/y' computation");
//                 cs.set("select/x'/num", y0);
//                 assert_eq!(cs.which_is_unsatisfied().unwrap(), "select/x' computation");
//             }
//         }
//     }

//     #[test]
//     fn test_edwards_addition() {
//         let params = &JubjubBn256::new();
//         let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

//         for _ in 0..100 {
//             let p1 = edwards::Point::<Bn256, _>::rand(rng, params);
//             let p2 = edwards::Point::<Bn256, _>::rand(rng, params);

//             let p3 = p1.add(&p2, params);

//             let (x0, y0) = p1.into_xy();
//             let (x1, y1) = p2.into_xy();
//             let (x2, y2) = p3.into_xy();

//             let mut cs = TestConstraintSystem::<Bn256>::new();

//             let num_x0 = AllocatedNum::alloc(cs.namespace(|| "x0"), || Ok(x0)).unwrap();
//             let num_y0 = AllocatedNum::alloc(cs.namespace(|| "y0"), || Ok(y0)).unwrap();

//             let num_x1 = AllocatedNum::alloc(cs.namespace(|| "x1"), || Ok(x1)).unwrap();
//             let num_y1 = AllocatedNum::alloc(cs.namespace(|| "y1"), || Ok(y1)).unwrap();

//             let p1 = EdwardsPoint {
//                 x: num_x0,
//                 y: num_y0,
//             };

//             let p2 = EdwardsPoint {
//                 x: num_x1,
//                 y: num_y1,
//             };

//             let p3 = p1.add(cs.namespace(|| "addition"), &p2, params).unwrap();

//             assert!(cs.is_satisfied());

//             assert!(p3.x.get_value().unwrap() == x2);
//             assert!(p3.y.get_value().unwrap() == y2);

//             // let u = cs.get("addition/U/num");
//             // cs.set("addition/U/num", rng.gen());
//             // assert_eq!(cs.which_is_unsatisfied(), Some("addition/U computation"));
//             // cs.set("addition/U/num", u);
//             // assert!(cs.is_satisfied());

//             let x3 = cs.get("addition/x3/num");
//             cs.set("addition/x3/num", rng.gen());
//             assert_eq!(cs.which_is_unsatisfied(), Some("addition/x3 computation"));
//             cs.set("addition/x3/num", x3);
//             assert!(cs.is_satisfied());

//             let y3 = cs.get("addition/y3/num");
//             cs.set("addition/y3/num", rng.gen());
//             assert_eq!(cs.which_is_unsatisfied(), Some("addition/y3 computation"));
//             cs.set("addition/y3/num", y3);
//             assert!(cs.is_satisfied());
//         }
//     }

//     #[test]
//     fn test_edwards_doubling() {
//         let params = &JubjubBn256::new();
//         let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

//         for _ in 0..100 {
//             let p1 = edwards::Point::<Bn256, _>::rand(rng, params);
//             let p2 = p1.double(params);

//             let (x0, y0) = p1.into_xy();
//             let (x1, y1) = p2.into_xy();

//             let mut cs = TestConstraintSystem::<Bn256>::new();

//             let num_x0 = AllocatedNum::alloc(cs.namespace(|| "x0"), || Ok(x0)).unwrap();
//             let num_y0 = AllocatedNum::alloc(cs.namespace(|| "y0"), || Ok(y0)).unwrap();

//             let p1 = EdwardsPoint {
//                 x: num_x0,
//                 y: num_y0,
//             };

//             let p2 = p1.double(cs.namespace(|| "doubling"), params).unwrap();

//             assert!(cs.is_satisfied());

//             assert!(p2.x.get_value().unwrap() == x1);
//             assert!(p2.y.get_value().unwrap() == y1);
//         }
//     }

//     #[test]
//     fn test_montgomery_addition() {
//         let params = &JubjubBn256::new();
//         let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

//         for _ in 0..100 {
//             let p1 = loop {
//                 let x: Fr = rng.gen();
//                 let s: bool = rng.gen();

//                 if let Some(p) = montgomery::Point::<Bn256, _>::get_for_x(x, s, params) {
//                     break p;
//                 }
//             };

//             let p2 = loop {
//                 let x: Fr = rng.gen();
//                 let s: bool = rng.gen();

//                 if let Some(p) = montgomery::Point::<Bn256, _>::get_for_x(x, s, params) {
//                     break p;
//                 }
//             };

//             let p3 = p1.add(&p2, params);

//             let (x0, y0) = p1.into_xy().unwrap();
//             let (x1, y1) = p2.into_xy().unwrap();
//             let (x2, y2) = p3.into_xy().unwrap();

//             let mut cs = TestConstraintSystem::<Bn256>::new();

//             let num_x0 = AllocatedNum::alloc(cs.namespace(|| "x0"), || Ok(x0)).unwrap();
//             let num_y0 = AllocatedNum::alloc(cs.namespace(|| "y0"), || Ok(y0)).unwrap();

//             let num_x1 = AllocatedNum::alloc(cs.namespace(|| "x1"), || Ok(x1)).unwrap();
//             let num_y1 = AllocatedNum::alloc(cs.namespace(|| "y1"), || Ok(y1)).unwrap();

//             let p1 = MontgomeryPoint {
//                 x: num_x0.into(),
//                 y: num_y0.into(),
//             };

//             let p2 = MontgomeryPoint {
//                 x: num_x1.into(),
//                 y: num_y1.into(),
//             };

//             let p3 = p1.add(cs.namespace(|| "addition"), &p2, params).unwrap();

//             assert!(cs.is_satisfied());

//             assert!(p3.x.get_value().unwrap() == x2);
//             assert!(p3.y.get_value().unwrap() == y2);

//             cs.set("addition/yprime/num", rng.gen());
//             assert_eq!(cs.which_is_unsatisfied(), Some("addition/evaluate yprime"));
//             cs.set("addition/yprime/num", y2);
//             assert!(cs.is_satisfied());

//             cs.set("addition/xprime/num", rng.gen());
//             assert_eq!(cs.which_is_unsatisfied(), Some("addition/evaluate xprime"));
//             cs.set("addition/xprime/num", x2);
//             assert!(cs.is_satisfied());

//             cs.set("addition/lambda/num", rng.gen());
//             assert_eq!(cs.which_is_unsatisfied(), Some("addition/evaluate lambda"));
//         }
//     }
// }
