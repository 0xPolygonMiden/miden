use alloc::vec::Vec;

use miden_air::trace::{
    decoder::{NUM_USER_OP_HELPERS, USER_OP_HELPERS_OFFSET},
    main_trace::MainTrace,
    AUX_TRACE_RAND_ELEMENTS, AUX_TRACE_WIDTH, DECODER_TRACE_OFFSET, MIN_TRACE_LEN,
    STACK_TRACE_OFFSET, TRACE_WIDTH,
};
use vm_core::{stack::MIN_STACK_DEPTH, ProgramInfo, StackInputs, StackOutputs, ZERO};
use winter_prover::{EvaluationFrame, Trace, TraceInfo};

use super::{
    chiplets::AuxTraceBuilder as ChipletsAuxTraceBuilder,
    decoder::AuxTraceBuilder as DecoderAuxTraceBuilder,
    stack::AuxTraceBuilder as StackAuxTraceBuilder, ColMatrix, Digest, Felt, FieldElement, Host,
    Process,
};

mod utils;
pub use utils::{AuxColumnBuilder, ChipletsLengths, TraceFragment, TraceLenSummary};

#[cfg(test)]
mod tests;

// VM EXECUTION TRACE
// ================================================================================================

pub struct AuxTraceBuilders {
    pub(crate) decoder: DecoderAuxTraceBuilder,
    pub(crate) stack: StackAuxTraceBuilder,
    pub(crate) chiplets: ChipletsAuxTraceBuilder,
}

/// Execution trace which is generated when a program is executed on the VM.
///
/// The trace consists of the following components:
/// - Main traces of System, Decoder, Operand Stack, Range Checker, and Auxiliary Co-Processor
///   components.
/// - Hints used during auxiliary trace segment construction.
/// - Metadata needed by the STARK prover.
pub struct ExecutionTrace {
    meta: Vec<u8>,
    trace_info: TraceInfo,
    main_trace: MainTrace,
    aux_trace_builders: AuxTraceBuilders,
    program_info: ProgramInfo,
    stack_outputs: StackOutputs,
    trace_len_summary: TraceLenSummary,
}

impl ExecutionTrace {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Builds an execution trace for the provided process.
    pub fn new<H>(process: Process<H>, stack_outputs: StackOutputs) -> Self
    where
        H: Host,
    {
        let program_hash = process.decoder.program_hash();

        // create a new program info instance with the underlying kernel
        let kernel = process.kernel().clone();
        let program_info = ProgramInfo::new(program_hash.into(), kernel);
        let (main_trace, aux_trace_builders, trace_len_summary) = finalize_trace(process);
        let trace_info = TraceInfo::new_multi_segment(
            TRACE_WIDTH,
            AUX_TRACE_WIDTH,
            AUX_TRACE_RAND_ELEMENTS,
            main_trace.num_rows(),
            vec![],
            true,
        );

        Self {
            meta: Vec::new(),
            trace_info,
            aux_trace_builders,
            main_trace,
            program_info,
            stack_outputs,
            trace_len_summary,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the program info of this execution trace.
    pub fn program_info(&self) -> &ProgramInfo {
        &self.program_info
    }

    /// Returns hash of the program execution of which resulted in this execution trace.
    pub fn program_hash(&self) -> &Digest {
        self.program_info.program_hash()
    }

    /// Returns outputs of the program execution which resulted in this execution trace.
    pub fn stack_outputs(&self) -> &StackOutputs {
        &self.stack_outputs
    }

    /// Returns the initial state of the top 16 stack registers.
    pub fn init_stack_state(&self) -> StackInputs {
        let mut result = [ZERO; MIN_STACK_DEPTH];
        for (i, result) in result.iter_mut().enumerate() {
            *result = self.main_trace.get_column(i + STACK_TRACE_OFFSET)[0];
        }
        result.into()
    }

    /// Returns the final state of the top 16 stack registers.
    pub fn last_stack_state(&self) -> StackOutputs {
        let last_step = self.last_step();
        let mut result = [ZERO; MIN_STACK_DEPTH];
        for (i, result) in result.iter_mut().enumerate() {
            *result = self.main_trace.get_column(i + STACK_TRACE_OFFSET)[last_step];
        }
        result.into()
    }

    /// Returns helper registers state at the specified `clk` of the VM
    pub fn get_user_op_helpers_at(&self, clk: u32) -> [Felt; NUM_USER_OP_HELPERS] {
        let mut result = [ZERO; NUM_USER_OP_HELPERS];
        for (i, result) in result.iter_mut().enumerate() {
            *result = self.main_trace.get_column(DECODER_TRACE_OFFSET + USER_OP_HELPERS_OFFSET + i)
                [clk as usize];
        }
        result
    }

    /// Returns the trace length.
    pub fn get_trace_len(&self) -> usize {
        self.main_trace.num_rows()
    }

    /// Returns a summary of the lengths of main, range and chiplet traces.
    pub fn trace_len_summary(&self) -> &TraceLenSummary {
        &self.trace_len_summary
    }

    /// Returns the trace meta data.
    pub fn meta(&self) -> &[u8] {
        &self.meta
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the index of the last row in the trace.
    fn last_step(&self) -> usize {
        self.length() - 1
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------
    #[cfg(feature = "std")]
    #[allow(dead_code)]
    pub fn print(&self) {
        let mut row = [ZERO; TRACE_WIDTH];
        for i in 0..self.length() {
            self.main_trace.read_row_into(i, &mut row);
            std::println!("{:?}", row.iter().map(|v| v.as_int()).collect::<Vec<_>>());
        }
    }

    #[cfg(test)]
    pub fn test_finalize_trace<H>(
        process: Process<H>,
    ) -> (MainTrace, AuxTraceBuilders, TraceLenSummary)
    where
        H: Host,
    {
        finalize_trace(process)
    }

    pub fn build_aux_trace<E>(&self, rand_elements: &[E]) -> Option<ColMatrix<E>>
    where
        E: FieldElement<BaseField = Felt>,
    {
        // add decoder's running product columns
        let decoder_aux_columns = self
            .aux_trace_builders
            .decoder
            .build_aux_columns(&self.main_trace, rand_elements);

        // add stack's running product columns
        let stack_aux_columns =
            self.aux_trace_builders.stack.build_aux_columns(&self.main_trace, rand_elements);

        // add the running product columns for the chiplets
        let chiplets = self
            .aux_trace_builders
            .chiplets
            .build_aux_columns(&self.main_trace, rand_elements);

        // combine all auxiliary columns into a single vector
        let aux_columns = decoder_aux_columns
            .into_iter()
            .chain(stack_aux_columns)
            .chain(chiplets)
            .collect::<Vec<_>>();

        Some(ColMatrix::new(aux_columns))
    }
}

// TRACE TRAIT IMPLEMENTATION
// ================================================================================================

impl Trace for ExecutionTrace {
    type BaseField = Felt;

    fn length(&self) -> usize {
        self.main_trace.num_rows()
    }

    fn main_segment(&self) -> &ColMatrix<Felt> {
        &self.main_trace
    }

    fn read_main_frame(&self, row_idx: usize, frame: &mut EvaluationFrame<Felt>) {
        let next_row_idx = (row_idx + 1) % self.length();
        self.main_trace.read_row_into(row_idx, frame.current_mut());
        self.main_trace.read_row_into(next_row_idx, frame.next_mut());
    }

    fn info(&self) -> &TraceInfo {
        &self.trace_info
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Converts a process into a set of execution trace columns for each component of the trace.
///
/// The process includes:
/// - Determining the length of the trace required to accommodate the longest trace column.
/// - Padding the columns to make sure all columns are of the same length.
/// - Inserting random values in the last row of all columns. This helps ensure that there are no
///   repeating patterns in each column and each column contains a least two distinct values. This,
///   in turn, ensures that polynomial degrees of all columns are stable.
fn finalize_trace<H>(process: Process<H>) -> (MainTrace, AuxTraceBuilders, TraceLenSummary)
where
    H: Host,
{
    let (system, decoder, stack, mut range, chiplets, _) = process.into_parts();

    let clk = system.clk();

    // Trace lengths of system and stack components must be equal to the number of executed cycles
    assert_eq!(clk.as_usize(), system.trace_len(), "inconsistent system trace lengths");
    assert_eq!(clk.as_usize(), decoder.trace_len(), "inconsistent decoder trace length");
    assert_eq!(clk.as_usize(), stack.trace_len(), "inconsistent stack trace lengths");

    // Add the range checks required by the chiplets to the range checker.
    chiplets.append_range_checks(&mut range);

    // Generate number of rows for the range trace.
    let range_table_len = range.get_number_range_checker_rows();

    // Get the trace length required to hold all execution trace steps.
    let max_len = range_table_len.max(clk.into()).max(chiplets.trace_len());

    // Pad the trace length to the next power of two and ensure that there is space for the
    // Rows to hold random values
    let trace_len = max_len.next_power_of_two();
    assert!(
        trace_len >= MIN_TRACE_LEN,
        "trace length must be at least {MIN_TRACE_LEN}, but was {trace_len}",
    );

    // Get the lengths of the traces: main, range, and chiplets
    let trace_len_summary =
        TraceLenSummary::new(clk.into(), range_table_len, ChipletsLengths::new(&chiplets));

    // Combine all trace segments into the main trace
    let system_trace = system.into_trace(trace_len);
    let decoder_trace = decoder.into_trace(trace_len);
    let stack_trace = stack.into_trace(trace_len);
    let chiplets_trace = chiplets.into_trace(trace_len);

    // Combine the range trace segment using the support lookup table
    let range_check_trace = range.into_trace_with_table(range_table_len, trace_len);

    let trace = system_trace
        .into_iter()
        .chain(decoder_trace.trace)
        .chain(stack_trace.trace)
        .chain(range_check_trace.trace)
        .chain(chiplets_trace.trace)
        .collect::<Vec<_>>();

    let aux_trace_builders = AuxTraceBuilders {
        decoder: decoder_trace.aux_builder,
        stack: StackAuxTraceBuilder,
        chiplets: chiplets_trace.aux_builder,
    };

    let main_trace = MainTrace::new(ColMatrix::new(trace), clk);

    (main_trace, aux_trace_builders, trace_len_summary)
}
