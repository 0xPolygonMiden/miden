use vm_core::{Felt, Operation, ONE, ZERO};

use crate::{ExecutionError, Process, QuadFelt};

// RANDOM LINEAR COMBINATION OPERATIONS
// ================================================================================================

impl Process {
    // COMBINE VALUES USING RANDOMNESS
    // --------------------------------------------------------------------------------------------
    /// Performs a single step in the computation of the random linear combination:
    ///
    /// \sum_{i=0}^k{\alpha_i \cdot \left(\frac{T_i(x) - T_i(z)}{x - z} +
    ///            \frac{T_i(x) - T_i(g \cdot z)}{x - g \cdot z} \right)}
    ///
    /// The instruction computes the numerators $\alpha_i \cdot (T_i(x) - T_i(z))$ and
    /// $\alpha_i \cdot (T_i(x) - T_i(g \cdot z))$ and stores the values in two accumulators $r$
    /// and $p$, respectively. This instruction is specialized to main trace columns i.e.
    /// the values $T_i(x)$ are base field elements.
    ///
    /// The instruction is used in the context of STARK proof verification in order to compute
    /// the queries of the DEEP composition polynomial for FRI. It works in combination with
    /// the `mem_stream` instruction where it is called 8 times in a row for each call to
    /// `mem_stream`.
    ///
    /// The stack transition of the instruction can be visualized as follows:
    ///
    /// Input:
    ///
    /// +------+------+------+------+------+------+------+------+------+------+------+------+------+------+------+---+
    /// |  T7  |  T6  |  T5  |  T4  |  T3  |  T2  |  T1  |  T0  |  p1  |  p0  |  r1  |  r0  |x_addr|z_addr|a_addr| - |
    /// +------+------+------+------+------+------+------+------+------+------+------+------+------+------+------+---+
    ///
    ///
    /// Output:
    ///
    /// +------+------+------+------+------+------+------+------+------+------+------+------+------+--------+--------+---+
    /// |  T0  |  T7  |  T6  |  T5  |  T4  |  T3  |  T2  |  T1  |  p1' |  p0' |  r1' |  r0' |x_addr|z_addr+1|a_addr+1| - |
    /// +------+------+------+------+------+------+------+------+------+------+------+------+------+--------+--------+---+
    ///
    ///
    /// Here:
    ///
    /// 1. Ti for i in 0..=7 stands for the the value of the i-th trace polynomial for the current
    ///    query i.e. T_i(x).
    /// 2. (p0, p1) stands for an extension field element accumulating the values for the quotients
    ///    with common denominator (x - gz).
    /// 3. (r0, r1) stands for an extension field element accumulating the values for the quotients
    ///    with common denominator (x - z).
    /// 4. x_addr is the memory address from which we are loading the Ti's using the MSTREAM
    ///    instruction.
    /// 5. z_addr is the memory address to the i-th OOD evaluations at z and gz i.e. T_i(z):=
    ///    (T_i(z)0, T_i(z)1) and T_i(gz):= (T_i(gz)0, T_i(gz)1).
    /// 6. a_addr is the memory address of the i-th random element alpha_i used in batching the
    ///    trace polynomial quotients.
    ///
    /// The instruction also makes use of the helper registers to hold the values of T_i(z), T_i(gz)
    /// and alpha_i during the course of its execution.
    pub(super) fn op_rcomb_base(&mut self) -> Result<(), ExecutionError> {
        // --- read the T_i(x) value from the stack -----------------------------------------------
        let [t7, t6, t5, t4, t3, t2, t1, t0] = self.get_trace_values();

        // --- read the randomness from memory ----------------------------------------------------
        let alpha = self.get_randomness()?;

        // --- read the OOD values from memory ----------------------------------------------------
        let [tz, tgz] = self.get_ood_values()?;

        // --- read the accumulator values from stack ---------------------------------------------
        let [p, r] = self.read_accumulators();

        // --- compute the updated accumulator values ---------------------------------------------
        let v0 = self.stack.get(7);
        let tx = QuadFelt::new(v0, ZERO);
        let [p_new, r_new] = [p + alpha * (tx - tgz), r + alpha * (tx - tz)];

        // --- rotate the top 8 elements of the stack ---------------------------------------------
        self.stack.set(0, t0);
        self.stack.set(1, t7);
        self.stack.set(2, t6);
        self.stack.set(3, t5);
        self.stack.set(4, t4);
        self.stack.set(5, t3);
        self.stack.set(6, t2);
        self.stack.set(7, t1);

        // --- update the accumulators ------------------------------------------------------------
        self.stack.set(8, p_new.to_base_elements()[1]);
        self.stack.set(9, p_new.to_base_elements()[0]);
        self.stack.set(10, r_new.to_base_elements()[1]);
        self.stack.set(11, r_new.to_base_elements()[0]);

        // --- update the memory pointers ---------------------------------------------------------
        self.stack.set(12, self.stack.get(12));
        self.stack.set(13, self.stack.get(13) + ONE);
        self.stack.set(14, self.stack.get(14) + ONE);

        // --- copy the rest of the stack ---------------------------------------------------------
        self.stack.copy_state(15);

        // --- set the helper registers -----------------------------------------------------------
        self.set_helper_reg(alpha, tz, tgz);

        Ok(())
    }

    //// HELPER METHODS
    //// ------------------------------------------------------------------------------------------

    /// Returns the top 8 elements of the operand stack.
    fn get_trace_values(&self) -> [Felt; 8] {
        let v7 = self.stack.get(0);
        let v6 = self.stack.get(1);
        let v5 = self.stack.get(2);
        let v4 = self.stack.get(3);
        let v3 = self.stack.get(4);
        let v2 = self.stack.get(5);
        let v1 = self.stack.get(6);
        let v0 = self.stack.get(7);

        [v7, v6, v5, v4, v3, v2, v1, v0]
    }

    /// Returns randomness.
    fn get_randomness(&mut self) -> Result<QuadFelt, ExecutionError> {
        let ctx = self.system.ctx();
        let addr = self.stack.get(14);
        let word = self.chiplets.read_mem(ctx, addr.as_int() as u32)?;
        let a0 = word[0];
        let a1 = word[1];

        Ok(QuadFelt::new(a0, a1))
    }

    /// Returns the OOD values.
    fn get_ood_values(&mut self) -> Result<[QuadFelt; 2], ExecutionError> {
        let ctx = self.system.ctx();
        let addr = self.stack.get(13);
        let word = self.chiplets.read_mem(ctx, addr.as_int() as u32)?;

        Ok([QuadFelt::new(word[0], word[1]), QuadFelt::new(word[2], word[3])])
    }

    /// Reads the accumulator values.
    fn read_accumulators(&self) -> [QuadFelt; 2] {
        let p1 = self.stack.get(8);
        let p0 = self.stack.get(9);
        let p = QuadFelt::new(p0, p1);

        let r1 = self.stack.get(10);
        let r0 = self.stack.get(11);
        let r = QuadFelt::new(r0, r1);

        [p, r]
    }

    /// Populates helper registers with OOD values and randomness.
    fn set_helper_reg(&mut self, alpha: QuadFelt, tz: QuadFelt, tgz: QuadFelt) {
        let [a0, a1] = alpha.to_base_elements();
        let [tz0, tz1] = tz.to_base_elements();
        let [tgz0, tgz1] = tgz.to_base_elements();
        let values = [tz0, tz1, tgz0, tgz1, a0, a1];
        self.decoder.set_user_op_helpers(Operation::RCombBase, &values);
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::{borrow::ToOwned, vec::Vec};

    use test_utils::{build_test, rand::rand_array, TRUNCATE_STACK_PROC};
    use vm_core::{Felt, FieldElement, Operation, StackInputs, ONE, ZERO};

    use crate::{ContextId, DefaultHost, Process, QuadFelt};

    #[test]
    fn rcombine_main() {
        // --- build stack inputs -----------------------------------------------------------------
        let mut inputs = rand_array::<Felt, 16>();

        // set x_addr to
        inputs[12] = Felt::ZERO;

        // set z_addr pointer to x_addr + offset, where offset is a large enough value.
        let offset = Felt::new(1000);
        inputs[13] = inputs[12] + offset;

        // set a_addr to z_addr + offset
        inputs[14] = inputs[13] + offset;
        inputs[15] = ZERO;
        inputs.reverse();

        // --- setup the operand stack ------------------------------------------------------------
        let mut host = DefaultHost::default();
        let stack_inputs = StackInputs::new(inputs.to_vec()).expect("inputs lenght too long");
        let mut process = Process::new_dummy_with_decoder_helpers(stack_inputs);

        // --- setup memory -----------------------------------------------------------------------
        let ctx = ContextId::root();
        let tztgz = rand_array::<Felt, 4>();
        process
            .chiplets
            .write_mem(
                ctx,
                inputs[2].as_int().try_into().expect("Shouldn't fail by construction"),
                tztgz,
            )
            .unwrap();

        let a = rand_array::<Felt, 4>();
        process
            .chiplets
            .write_mem(
                ctx,
                inputs[1].as_int().try_into().expect("Shouldn't fail by construction"),
                a,
            )
            .unwrap();
        process.execute_op(Operation::Noop, &mut host).unwrap();

        // --- execute RCOMB1 operation -----------------------------------------------------------
        process.execute_op(Operation::RCombBase, &mut host).unwrap();

        // --- check that the top 8 stack elements are correctly rotated --------------------------
        let stack_state = process.stack.trace_state();
        inputs.reverse();
        assert_eq!(stack_state[1], inputs[0]);
        assert_eq!(stack_state[2], inputs[1]);
        assert_eq!(stack_state[3], inputs[2]);
        assert_eq!(stack_state[4], inputs[3]);
        assert_eq!(stack_state[5], inputs[4]);
        assert_eq!(stack_state[6], inputs[5]);
        assert_eq!(stack_state[7], inputs[6]);
        assert_eq!(stack_state[0], inputs[7]);

        // --- check that the accumulator was updated correctly -----------------------------------
        let p1 = inputs[8];
        let p0 = inputs[9];
        let p = QuadFelt::new(p0, p1);

        let r1 = inputs[10];
        let r0 = inputs[11];
        let r = QuadFelt::new(r0, r1);

        let tz0 = tztgz[0];
        let tz1 = tztgz[1];
        let tz = QuadFelt::new(tz0, tz1);
        let tgz0 = tztgz[2];
        let tgz1 = tztgz[3];
        let tgz = QuadFelt::new(tgz0, tgz1);

        let tx = QuadFelt::new(inputs[7], ZERO);

        let a0 = a[0];
        let a1 = a[1];
        let alpha = QuadFelt::new(a0, a1);

        let p_new = p + alpha * (tx - tgz);
        let r_new = r + alpha * (tx - tz);

        assert_eq!(p_new.to_base_elements()[1], stack_state[8]);
        assert_eq!(p_new.to_base_elements()[0], stack_state[9]);
        assert_eq!(r_new.to_base_elements()[1], stack_state[10]);
        assert_eq!(r_new.to_base_elements()[0], stack_state[11]);

        // --- check that memory pointers were updated --------------------------------------------
        assert_eq!(inputs[12], stack_state[12]);
        assert_eq!(inputs[13] + ONE, stack_state[13]);
        assert_eq!(inputs[14] + ONE, stack_state[14]);

        // --- check that the helper registers were updated correctly -----------------------------
        let helper_reg_expected = [tz0, tz1, tgz0, tgz1, a0, a1];
        assert_eq!(helper_reg_expected, process.decoder.get_user_op_helpers());
    }

    #[test]
    fn prove_verify() {
        let source = format!(
            "
            {TRUNCATE_STACK_PROC}

            begin
                # I) Prepare memory and stack

                # 1) Load T_i(x) for i=0,..,7
                push.0 padw
                adv_pipe

                # 2) Load [T_i(z), T_i(gz)] for i=0,..,7
                repeat.4
                    adv_pipe
                end

                # 3) Load [a0, a1, 0, 0] for i=0,..,7
                repeat.4
                    adv_pipe
                end

                # 4) Clean up stack
                dropw dropw dropw drop

                # 5) Prepare stack

                ## a) Push pointers
                push.10     # a_ptr
                push.2      # z_ptr
                push.0      # x_ptr

                ## b) Push accumulators
                padw

                ## c) Add padding for mem_stream
                padw padw

                # II) Execute `rcomb_base` op
                mem_stream
                repeat.8
                    rcomb_base
                end

                exec.truncate_stack
            end
        "
        );

        // generate the data
        let tx: [Felt; 8] = rand_array();
        let tz_tgz: [QuadFelt; 16] = rand_array();
        let a: [QuadFelt; 8] = rand_array();

        // compute the expected values of the accumulators
        let mut p = QuadFelt::ZERO;
        let mut r = QuadFelt::ZERO;
        let tz: Vec<QuadFelt> = tz_tgz.iter().step_by(2).map(|e| e.to_owned()).collect();
        let tgz: Vec<QuadFelt> = tz_tgz.iter().skip(1).step_by(2).map(|e| e.to_owned()).collect();
        for i in 0..8 {
            p += a[i] * (QuadFelt::from(tx[i]) - tgz[i]);
            r += a[i] * (QuadFelt::from(tx[i]) - tz[i]);
        }

        // prepare the advice stack with the generated data
        let mut adv_stack = Vec::new();
        let tz_tgz: Vec<Felt> = tz_tgz.iter().flat_map(|e| e.to_base_elements()).collect();
        let a: Vec<Felt> = a
            .iter()
            .flat_map(|e| {
                let element = e.to_base_elements();
                [element[0], element[1], ZERO, ZERO]
            })
            .collect();
        adv_stack.extend_from_slice(&tx);
        adv_stack.extend_from_slice(&tz_tgz);
        adv_stack.extend_from_slice(&a);
        let adv_stack: Vec<u64> = adv_stack.iter().map(|e| e.as_int()).collect();

        // create the expected operand stack
        let mut expected = Vec::new();
        // updated pointers
        expected.extend_from_slice(&[ZERO, Felt::from(18_u8), Felt::from(10_u8), Felt::from(2_u8)]);
        // updated accumulators
        expected.extend_from_slice(&[
            r.to_base_elements()[0],
            r.to_base_elements()[1],
            p.to_base_elements()[0],
            p.to_base_elements()[1],
        ]);
        // the top 8 stack elements should equal tx since 8 calls to `rcomb_base` implies 8 circular
        // shifts of the top 8 elements i.e., the identity map on the top 8 element.
        expected.extend_from_slice(&tx);
        let expected: Vec<u64> = expected.iter().rev().map(|e| e.as_int()).collect();

        let test = build_test!(source, &[], &adv_stack);
        test.expect_stack(&expected);

        let pub_inputs: Vec<u64> = Vec::new();
        test.prove_and_verify(pub_inputs, false);
    }
}
