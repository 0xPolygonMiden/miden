#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::vec::Vec;
use core::marker::PhantomData;

use decoder::{DECODER_OP_BITS_OFFSET, DECODER_USER_OP_HELPERS_OFFSET};
use vm_core::{
    utils::{ByteReader, ByteWriter, Deserializable, Serializable},
    ExtensionOf, ProgramInfo, StackInputs, StackOutputs, ONE, ZERO,
};
use winter_air::{
    Air, AirContext, Assertion, EvaluationFrame, LogUpGkrEvaluator, LogUpGkrOracle,
    ProofOptions as WinterProofOptions, TraceInfo, TransitionConstraintDegree,
};
use winter_prover::matrix::ColMatrix;

mod constraints;
pub use constraints::stack;
use constraints::{chiplets, range};

pub mod trace;
pub use trace::rows::RowIndex;
use trace::{
    chiplets::{MEMORY_D0_COL_IDX, MEMORY_D1_COL_IDX},
    range::{M_COL_IDX, V_COL_IDX},
    *,
};

mod errors;
mod options;
mod proof;

mod utils;
// RE-EXPORTS
// ================================================================================================
pub use errors::ExecutionOptionsError;
pub use options::{ExecutionOptions, ProvingOptions};
pub use proof::{ExecutionProof, HashFunction};
use utils::TransitionConstraintRange;
pub use vm_core::{
    utils::{DeserializationError, ToElements},
    Felt, FieldElement, StarkField,
};
pub use winter_air::{AuxRandElements, FieldExtension, LagrangeKernelEvaluationFrame};

// PROCESSOR AIR
// ================================================================================================

/// TODO: add docs
pub struct ProcessorAir {
    context: AirContext<Felt, PublicInputs>,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    constraint_ranges: TransitionConstraintRange,
}

impl ProcessorAir {
    /// Returns last step of the execution trace.
    pub fn last_step(&self) -> usize {
        self.trace_length() - self.context().num_transition_exemptions()
    }
}

impl Air for ProcessorAir {
    type BaseField = Felt;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: WinterProofOptions) -> Self {
        // --- system -----------------------------------------------------------------------------
        let mut main_degrees = vec![
            TransitionConstraintDegree::new(1), // clk' = clk + 1
        ];

        // --- stack constraints -------------------------------------------------------------------
        let mut stack_degrees = stack::get_transition_constraint_degrees();
        main_degrees.append(&mut stack_degrees);

        // --- range checker ----------------------------------------------------------------------
        let mut range_checker_degrees = range::get_transition_constraint_degrees();
        main_degrees.append(&mut range_checker_degrees);

        // --- chiplets (hasher, bitwise, memory) -------------------------
        let mut chiplets_degrees = chiplets::get_transition_constraint_degrees();
        main_degrees.append(&mut chiplets_degrees);

        // Define the transition constraint ranges.
        let constraint_ranges = TransitionConstraintRange::new(
            1,
            stack::get_transition_constraint_count(),
            range::get_transition_constraint_count(),
            chiplets::get_transition_constraint_count(),
        );

        // Define the number of boundary constraints for the main execution trace segment.
        // TODO: determine dynamically
        let num_main_assertions = 2 + stack::NUM_ASSERTIONS + range::NUM_ASSERTIONS;

        // Define the number of boundary constraints for the auxiliary execution trace segment.
        let num_aux_assertions = stack::NUM_AUX_ASSERTIONS;

        // Create the context and set the number of transition constraint exemptions to two; this
        // allows us to inject random values into the last row of the execution trace.
        let context = AirContext::new_multi_segment(
            trace_info,
            pub_inputs.clone(),
            main_degrees,
            vec![],
            num_main_assertions,
            num_aux_assertions,
            options,
        )
        .set_num_transition_exemptions(2);

        Self {
            context,
            stack_inputs: pub_inputs.stack_inputs,
            stack_outputs: pub_inputs.stack_outputs,
            constraint_ranges,
        }
    }

    // PERIODIC COLUMNS
    // --------------------------------------------------------------------------------------------

    /// Returns a set of periodic columns for the ProcessorAir.
    fn get_periodic_column_values(&self) -> Vec<Vec<Felt>> {
        chiplets::get_periodic_column_values()
    }

    // ASSERTIONS
    // --------------------------------------------------------------------------------------------

    #[allow(clippy::vec_init_then_push)]
    fn get_assertions(&self) -> Vec<Assertion<Felt>> {
        let mut result = Vec::new();

        // --- set assertions for the first step --------------------------------------------------
        // first value of clk is 0
        result.push(Assertion::single(CLK_COL_IDX, 0, ZERO));

        // first value of fmp is 2^30
        result.push(Assertion::single(FMP_COL_IDX, 0, Felt::new(2u64.pow(30))));

        // add initial assertions for the stack.
        stack::get_assertions_first_step(&mut result, &*self.stack_inputs);

        // Add initial assertions for the range checker.
        range::get_assertions_first_step(&mut result);

        // --- set assertions for the last step ---------------------------------------------------
        let last_step = self.last_step();

        // add the stack's assertions for the last step.
        stack::get_assertions_last_step(&mut result, last_step, &self.stack_outputs);

        // Add the range checker's assertions for the last step.
        range::get_assertions_last_step(&mut result, last_step);

        result
    }

    fn get_aux_assertions<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        _aux_rand_elements: &AuxRandElements<E>,
    ) -> Vec<Assertion<E>> {
        let mut result: Vec<Assertion<E>> = Vec::new();

        // --- set assertions for the first step --------------------------------------------------

        // add initial assertions for the stack's auxiliary columns.
        stack::get_aux_assertions_first_step(&mut result);

        // --- set assertions for the last step ---------------------------------------------------
        let last_step = self.last_step();

        // add the stack's auxiliary column assertions for the last step.
        stack::get_aux_assertions_last_step(&mut result, last_step);

        result
    }

    // TRANSITION CONSTRAINTS
    // --------------------------------------------------------------------------------------------

    fn evaluate_transition<E: FieldElement<BaseField = Felt>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        // --- system -----------------------------------------------------------------------------
        // clk' = clk + 1
        result[0] = next[CLK_COL_IDX] - (current[CLK_COL_IDX] + E::ONE);

        // --- stack operations -------------------------------------------------------------------
        stack::enforce_constraints::<E>(
            frame,
            select_result_range!(result, self.constraint_ranges.stack),
        );

        // --- range checker ----------------------------------------------------------------------
        range::enforce_constraints::<E>(
            frame,
            select_result_range!(result, self.constraint_ranges.range_checker),
        );

        // --- chiplets (hasher, bitwise, memory) -------------------------
        chiplets::enforce_constraints::<E>(
            frame,
            periodic_values,
            select_result_range!(result, self.constraint_ranges.chiplets),
        );
    }

    fn evaluate_aux_transition<F, E>(
        &self,
        _main_frame: &EvaluationFrame<F>,
        _aux_frame: &EvaluationFrame<E>,
        _periodic_values: &[F],
        _aux_rand_elements: &AuxRandElements<E>,
        _result: &mut [E],
    ) where
        F: FieldElement<BaseField = Felt>,
        E: FieldElement<BaseField = Felt> + ExtensionOf<F>,
    {
    }

    fn context(&self) -> &AirContext<Felt, PublicInputs> {
        &self.context
    }

    fn get_logup_gkr_evaluator(
        &self,
    ) -> impl LogUpGkrEvaluator<BaseField = Self::BaseField, PublicInputs = Self::PublicInputs>
    {
        MidenLogUpGkrEval::new()
    }
}

// PUBLIC INPUTS
// ================================================================================================

#[derive(Clone, Debug)]
pub struct PublicInputs {
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
}

impl PublicInputs {
    pub fn new(
        program_info: ProgramInfo,
        stack_inputs: StackInputs,
        stack_outputs: StackOutputs,
    ) -> Self {
        Self {
            program_info,
            stack_inputs,
            stack_outputs,
        }
    }
}

impl vm_core::ToElements<Felt> for PublicInputs {
    fn to_elements(&self) -> Vec<Felt> {
        let mut result = self.program_info.to_elements();
        result.append(&mut self.stack_inputs.to_vec());
        result.append(&mut self.stack_outputs.to_vec());
        result
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for PublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.program_info.write_into(target);
        self.stack_inputs.write_into(target);
        self.stack_outputs.write_into(target);
    }
}

impl Deserializable for PublicInputs {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let program_info = ProgramInfo::read_from(source)?;
        let stack_inputs = StackInputs::read_from(source)?;
        let stack_outputs = StackOutputs::read_from(source)?;

        Ok(PublicInputs {
            program_info,
            stack_inputs,
            stack_outputs,
        })
    }
}

// LOGUP-GKR
// ================================================================================================

#[derive(Clone, Default)]
pub struct MidenLogUpGkrEval<B: FieldElement + StarkField> {
    oracles: Vec<LogUpGkrOracle>,
    _field: PhantomData<B>,
}

impl<B: FieldElement + StarkField> MidenLogUpGkrEval<B> {
    pub fn new() -> Self {
        let oracles = (0..TRACE_WIDTH).map(LogUpGkrOracle::CurrentRow).collect();
        Self { oracles, _field: PhantomData }
    }
}

impl LogUpGkrEvaluator for MidenLogUpGkrEval<Felt> {
    type BaseField = Felt;

    type PublicInputs = PublicInputs;

    fn get_oracles(&self) -> &[LogUpGkrOracle] {
        &self.oracles
    }

    fn get_num_rand_values(&self) -> usize {
        1
    }

    fn get_num_fractions(&self) -> usize {
        8
    }

    fn max_degree(&self) -> usize {
        5
    }

    fn build_query<E>(&self, frame: &EvaluationFrame<E>, query: &mut [E])
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        query.iter_mut().zip(frame.current().iter()).for_each(|(q, f)| *q = *f)
    }

    fn evaluate_query<F, E>(
        &self,
        query: &[F],
        _periodic_values: &[F],
        rand_values: &[E],
        numerator: &mut [E],
        denominator: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + ExtensionOf<F>,
    {
        assert_eq!(numerator.len(), 8);
        assert_eq!(denominator.len(), 8);
        assert_eq!(query.len(), TRACE_WIDTH);

        // numerators
        let multiplicity = query[M_COL_IDX];
        let f_m = {
            let mem_selec0 = query[CHIPLETS_OFFSET];
            let mem_selec1 = query[CHIPLETS_OFFSET + 1];
            let mem_selec2 = query[CHIPLETS_OFFSET + 2];
            mem_selec0 * mem_selec1 * (F::ONE - mem_selec2)
        };

        let f_rc = {
            let op_bit_4 = query[DECODER_OP_BITS_OFFSET + 4];
            let op_bit_5 = query[DECODER_OP_BITS_OFFSET + 5];
            let op_bit_6 = query[DECODER_OP_BITS_OFFSET + 6];

            (F::ONE - op_bit_4) * (F::ONE - op_bit_5) * op_bit_6
        };
        numerator[0] = E::from(multiplicity);
        numerator[1] = E::from(f_m);
        numerator[2] = E::from(f_m);
        numerator[3] = E::from(f_rc);
        numerator[4] = E::from(f_rc);
        numerator[5] = E::from(f_rc);
        numerator[6] = E::from(f_rc);
        numerator[7] = E::ZERO;

        // denominators
        let alpha = rand_values[0];

        let table_denom = alpha - E::from(query[V_COL_IDX]);
        let memory_denom_0 = -(alpha - E::from(query[MEMORY_D0_COL_IDX]));
        let memory_denom_1 = -(alpha - E::from(query[MEMORY_D1_COL_IDX]));
        let stack_value_denom_0 = -(alpha - E::from(query[DECODER_USER_OP_HELPERS_OFFSET]));
        let stack_value_denom_1 = -(alpha - E::from(query[DECODER_USER_OP_HELPERS_OFFSET + 1]));
        let stack_value_denom_2 = -(alpha - E::from(query[DECODER_USER_OP_HELPERS_OFFSET + 2]));
        let stack_value_denom_3 = -(alpha - E::from(query[DECODER_USER_OP_HELPERS_OFFSET + 3]));

        denominator[0] = table_denom;
        denominator[1] = memory_denom_0;
        denominator[2] = memory_denom_1;
        denominator[3] = stack_value_denom_0;
        denominator[4] = stack_value_denom_1;
        denominator[5] = stack_value_denom_2;
        denominator[6] = stack_value_denom_3;
        denominator[7] = E::ONE;
    }

    fn compute_claim<E>(&self, _inputs: &Self::PublicInputs, _rand_values: &[E]) -> E
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        E::ZERO
    }
}
