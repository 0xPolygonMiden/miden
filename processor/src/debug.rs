use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

use miden_air::RowIndex;
use vm_core::{AssemblyOp, Operation, StackOutputs, Word};

use crate::{
    range::RangeChecker, system::ContextId, Chiplets, ChipletsLengths, Decoder, ExecutionError,
    Felt, Process, Stack, System, TraceLenSummary,
};

/// VmState holds a current process state information at a specific clock cycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmState {
    pub clk: RowIndex,
    pub ctx: ContextId,
    pub op: Option<Operation>,
    pub asmop: Option<AsmOpInfo>,
    pub fmp: Felt,
    pub stack: Vec<Felt>,
    pub memory: Vec<(u64, Word)>,
}

impl fmt::Display for VmState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let stack: Vec<u64> = self.stack.iter().map(|x| x.as_int()).collect();
        let memory: Vec<(u64, [u64; 4])> =
            self.memory.iter().map(|x| (x.0, word_to_ints(&x.1))).collect();
        write!(
            f,
            "clk={}{}{}, fmp={}, stack={stack:?}, memory={memory:?}",
            self.clk,
            match self.op {
                Some(op) => format!(", op={op}"),
                None => "".to_string(),
            },
            match &self.asmop {
                Some(op) => format!(", {op}"),
                None => "".to_string(),
            },
            self.fmp
        )
    }
}

/// Iterator that iterates through vm state at each step of the execution.
///
/// This allows debugging or replaying ability to view various process state at each clock cycle. If
/// the execution returned an error, it returns that error on the clock cycle it stopped.
pub struct VmStateIterator {
    chiplets: Chiplets,
    decoder: Decoder,
    stack: Stack,
    system: System,
    error: Option<ExecutionError>,
    clk: RowIndex,
    asmop_idx: usize,
    forward: bool,
    trace_len_summary: TraceLenSummary,
}

impl VmStateIterator {
    pub fn new(process: Process, result: Result<StackOutputs, ExecutionError>) -> Self {
        let (system, decoder, stack, mut range, chiplets) = process.into_parts();
        let trace_len_summary = Self::build_trace_len_summary(&system, &mut range, &chiplets);

        Self {
            chiplets,
            decoder,
            stack,
            system,
            error: result.err(),
            clk: RowIndex::from(0),
            asmop_idx: 0,
            forward: true,
            trace_len_summary,
        }
    }

    /// Returns the asm op info corresponding to this vm state and whether this is the start of
    /// operation sequence corresponding to current assembly instruction.
    fn get_asmop(&self) -> (Option<AsmOpInfo>, bool) {
        let assembly_ops = self.decoder.debug_info().assembly_ops();

        if self.clk == 0 || assembly_ops.is_empty() || self.asmop_idx > assembly_ops.len() {
            return (None, false);
        }

        // keeps track of the next assembly op in the list. It's the same as the current asmop
        // when the current asmop is last in the list
        let next_asmop = if self.forward && self.asmop_idx < assembly_ops.len() {
            &assembly_ops[self.asmop_idx]
        } else {
            &assembly_ops[self.asmop_idx.saturating_sub(1)]
        };

        // keeps track of the current assembly op in the list. It's the same as the next asmop
        // when the clock cycle is less than the clock cycle of the first asmop.
        let (curr_asmop, cycle_idx) = if self.asmop_idx > 0 {
            let a = self.clk;
            let b = RowIndex::from(assembly_ops[self.asmop_idx - 1].0);
            (
                &assembly_ops[self.asmop_idx - 1],
                // difference between current clock cycle and start clock cycle of the current
                // asmop
                (a.max(b) - a.min(b)) as u8,
            )
        } else {
            (next_asmop, 0) //dummy value, never used.
        };

        // if this is the first op in the sequence corresponding to the next asmop, returns a new
        // instance of [AsmOp] instantiated with next asmop, num_cycles and cycle_idx of 1.
        if next_asmop.0 == (self.clk - 1).as_usize() {
            // cycle_idx starts at 1 instead of 0 to remove ambiguity
            let cycle_idx = 1;
            let asmop = AsmOpInfo::new(next_asmop.1.clone(), cycle_idx);
            (Some(asmop), true)
        }
        // if this is not the first asmop in the list and if this op is part of current asmop,
        // returns a new instance of [AsmOp] instantiated with current asmop, num_cycles and
        // cycle_idx of current op.
        else if self.asmop_idx > 0 && cycle_idx <= curr_asmop.1.num_cycles() {
            // diff between curr clock cycle and start clock cycle of the current asmop
            let asmop = AsmOpInfo::new(curr_asmop.1.clone(), cycle_idx);
            (Some(asmop), false)
        }
        // if the next asmop is the first in the list and is at a greater than current clock cycle
        // or if the current op is not a part of any asmop, return None.
        else {
            (None, false)
        }
    }

    pub fn back(&mut self) -> Option<VmState> {
        if self.clk == 0 {
            return None;
        }

        // if we are changing directions we must decrement the clk counter.
        if self.forward {
            self.clk = self.clk.saturating_sub(1);
            self.forward = false;
        }

        let ctx = self.system.get_ctx_at(self.clk);

        let op = if self.clk == 0 {
            None
        } else {
            Some(self.decoder.debug_info().operations()[self.clk - 1])
        };

        let (asmop, is_start) = self.get_asmop();
        if is_start {
            self.asmop_idx -= 1;
        }

        let result = Some(VmState {
            clk: self.clk,
            ctx,
            op,
            asmop,
            fmp: self.system.get_fmp_at(self.clk),
            stack: self.stack.get_state_at(self.clk),
            memory: self.chiplets.get_mem_state_at(ctx, self.clk),
        });

        self.clk -= 1;

        result
    }

    pub fn into_parts(self) -> (System, Decoder, Stack, Chiplets, Option<ExecutionError>) {
        (self.system, self.decoder, self.stack, self.chiplets, self.error)
    }

    pub fn trace_len_summary(&self) -> &TraceLenSummary {
        &self.trace_len_summary
    }

    /// Returns an instance of [TraceLenSummary] based on provided data.
    fn build_trace_len_summary(
        system: &System,
        range: &mut RangeChecker,
        chiplets: &Chiplets,
    ) -> TraceLenSummary {
        let clk = system.clk();
        let range_table_len = range.get_number_range_checker_rows();
        chiplets.append_range_checks(range);

        TraceLenSummary::new(clk.into(), range_table_len, ChipletsLengths::new(chiplets))
    }
}

impl Iterator for VmStateIterator {
    type Item = Result<VmState, ExecutionError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.clk > self.system.clk() {
            match &self.error {
                Some(_) => {
                    let error = core::mem::take(&mut self.error);
                    return Some(Err(error.unwrap()));
                },
                None => return None,
            }
        }

        // if we are changing iteration directions we must increment the clk counter
        if !self.forward && self.clk < self.system.clk() {
            self.clk += 1;
            self.forward = true;
        }

        let ctx = self.system.get_ctx_at(self.clk);

        let op = if self.clk == 0 {
            None
        } else {
            Some(self.decoder.debug_info().operations()[self.clk - 1])
        };

        let (asmop, is_start) = self.get_asmop();
        if is_start {
            self.asmop_idx += 1;
        }

        let result = Some(Ok(VmState {
            clk: self.clk,
            ctx,
            op,
            asmop,
            fmp: self.system.get_fmp_at(self.clk),
            stack: self.stack.get_state_at(self.clk),
            memory: self.chiplets.get_mem_state_at(ctx, self.clk),
        }));

        self.clk += 1;

        result
    }
}

// HELPER FUNCTIONS
// ================================================================================================
fn word_to_ints(word: &Word) -> [u64; 4] {
    [word[0].as_int(), word[1].as_int(), word[2].as_int(), word[3].as_int()]
}

/// Contains assembly instruction and operation index in the sequence corresponding to the specified
/// AsmOp decorator. This index starts from 1 instead of 0.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsmOpInfo {
    asmop: AssemblyOp,
    cycle_idx: u8,
}

// ASMOP STATE
// =================================================================

impl AsmOpInfo {
    /// Returns [AsmOpInfo] instantiated with the specified assembly instruction string, number of
    /// cycles it takes to execute the assembly instruction and op index in sequence of operations
    /// corresponding to the current assembly instruction. The first index is 1 instead of 0.
    pub fn new(asmop: AssemblyOp, cycle_idx: u8) -> Self {
        Self { asmop, cycle_idx }
    }

    /// Returns the context name for this operation.
    pub fn context_name(&self) -> &str {
        self.asmop.context_name()
    }

    /// Returns the assembly instruction corresponding to this state.
    pub fn op(&self) -> &str {
        self.asmop.op()
    }

    /// Returns the gerneralized form of assembly instruction corresponding to this state.
    pub fn op_generalized(&self) -> String {
        let op_vec: Vec<&str> = self.op().split('.').collect();
        let keep_params = matches!(op_vec[0], "movdn" | "movup");
        if !keep_params && op_vec.last().unwrap().parse::<usize>().is_ok() {
            op_vec.split_last().unwrap().1.join(".")
        } else {
            self.op().to_string()
        }
    }

    /// Returns the number of VM cycles taken to execute the assembly instruction.
    pub fn num_cycles(&self) -> u8 {
        self.asmop.num_cycles()
    }

    /// Returns the operation index of the operation at the specified clock cycle in the sequence
    /// of operations corresponding to the current assembly instruction.
    pub fn cycle_idx(&self) -> u8 {
        self.cycle_idx
    }

    /// Returns `true` if the debug should break for this line.
    pub const fn should_break(&self) -> bool {
        self.asmop.should_break()
    }
}

impl fmt::Display for AsmOpInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, cycles={}", self.asmop, self.cycle_idx)
    }
}

impl AsRef<AssemblyOp> for AsmOpInfo {
    #[inline]
    fn as_ref(&self) -> &AssemblyOp {
        &self.asmop
    }
}
