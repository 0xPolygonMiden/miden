use alloc::{
    collections::{btree_map::Entry, BTreeMap},
    vec::Vec,
};

use miden_air::{
    trace::chiplets::memory::{Selectors, MEMORY_COPY_READ, MEMORY_INIT_READ, MEMORY_WRITE},
    RowIndex,
};

use super::{Felt, Word, INIT_MEM_VALUE};
use crate::{ContextId, ExecutionError};

// MEMORY SEGMENT TRACE
// ================================================================================================

/// Memory access trace for a single segment sorted first by address and then by clock cycle.
///
/// A memory segment is an isolated address space accessible from a specific execution context.
/// Within each segment, the memory is word-addressable. That is, four field elements are located
/// at each memory address, and we can read and write elements to/from memory in batches of four.
#[derive(Debug, Default)]
pub struct MemorySegmentTrace(BTreeMap<u32, Vec<MemorySegmentAccess>>);

impl MemorySegmentTrace {
    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a word located at the specified address, or None if the address hasn't been
    /// accessed previously.
    ///
    /// Unlike read() which modifies the memory access trace, this method returns the value at the
    /// specified address (if one exists) without altering the memory access trace.
    pub fn get_value(&self, addr: u32) -> Option<Word> {
        match self.0.get(&addr) {
            Some(addr_trace) => addr_trace.last().map(|access| access.value()),
            None => None,
        }
    }

    /// Returns the entire memory state at the beginning of the specified cycle.
    pub fn get_state_at(&self, clk: RowIndex) -> Vec<(u32, Word)> {
        let mut result: Vec<(u32, Word)> = Vec::new();

        if clk == 0 {
            return result;
        }

        // since we record memory state at the end of a given cycle, to get memory state at the end
        // of a cycle, we need to look at the previous cycle. that is, memory state at the end of
        // the previous cycle is the same as memory state the the beginning of the current cycle.
        let search_clk: u64 = (clk - 1).into();

        for (&addr, addr_trace) in self.0.iter() {
            match addr_trace.binary_search_by(|access| access.clk().as_int().cmp(&search_clk)) {
                Ok(i) => result.push((addr, addr_trace[i].value())),
                Err(i) => {
                    // Binary search finds the index of the data with the specified clock cycle.
                    // Decrement the index to get the trace from the previously accessed clock
                    // cycle to insert into the results.
                    if i > 0 {
                        result.push((addr, addr_trace[i - 1].value()));
                    }
                },
            }
        }

        result
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Returns a word located in memory at the specified address. The memory access is assumed
    /// to happen at the provided clock cycle.
    ///
    /// If the specified address hasn't been previously written to, four ZERO elements are
    /// returned. This effectively implies that memory is initialized to ZERO.
    ///
    /// # Errors
    /// - Returns an error if the same address is accessed more than once in the same clock cycle.
    pub fn read(&mut self, ctx: ContextId, addr: u32, clk: Felt) -> Result<Word, ExecutionError> {
        // look up the previous value in the appropriate address trace and add (clk, prev_value)
        // to it; if this is the first time we access this address, create address trace for it
        // with entry (clk, [ZERO, 4]). in both cases, return the last value in the address trace.
        match self.0.entry(addr) {
            Entry::Vacant(vacant_entry) => {
                let access =
                    MemorySegmentAccess::new(clk, MemoryOperation::InitRead, INIT_MEM_VALUE);
                vacant_entry.insert(vec![access]);
                Ok(INIT_MEM_VALUE)
            },
            Entry::Occupied(mut occupied_entry) => {
                let addr_trace = occupied_entry.get_mut();
                if addr_trace.last().expect("empty address trace").clk() == clk {
                    Err(ExecutionError::DuplicateMemoryAccess { ctx, addr, clk })
                } else {
                    let last_value = addr_trace.last().expect("empty address trace").value();
                    let access =
                        MemorySegmentAccess::new(clk, MemoryOperation::CopyRead, last_value);
                    addr_trace.push(access);

                    Ok(last_value)
                }
            },
        }
    }

    /// Writes the provided word at the specified address. The memory access is assumed to happen
    /// at the provided clock cycle.
    ///
    /// # Errors
    /// - Returns an error if the same address is accessed more than once in the same clock cycle.
    pub fn write(
        &mut self,
        ctx: ContextId,
        addr: u32,
        clk: Felt,
        value: Word,
    ) -> Result<(), ExecutionError> {
        // add a memory access to the appropriate address trace; if this is the first time
        // we access this address, initialize address trace.
        let access = MemorySegmentAccess::new(clk, MemoryOperation::Write, value);
        match self.0.entry(addr) {
            Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(vec![access]);
                Ok(())
            },
            Entry::Occupied(mut occupied_entry) => {
                let addr_trace = occupied_entry.get_mut();
                if addr_trace.last().expect("empty address trace").clk() == clk {
                    Err(ExecutionError::DuplicateMemoryAccess { ctx, addr, clk })
                } else {
                    addr_trace.push(access);
                    Ok(())
                }
            },
        }
    }

    // INNER VALUE ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the map underlying this memory segment trace.
    pub(super) fn inner(&self) -> &BTreeMap<u32, Vec<MemorySegmentAccess>> {
        &self.0
    }

    /// Returns a map underlying this memory segment trace while consuming self.
    pub(super) fn into_inner(self) -> BTreeMap<u32, Vec<MemorySegmentAccess>> {
        self.0
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Returns current size (in words) of this memory segment.
    #[cfg(test)]
    pub fn size(&self) -> usize {
        self.0.len()
    }
}

// MEMORY ACCESS
// ================================================================================================

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MemoryOperation {
    InitRead,
    CopyRead,
    Write,
}

/// A single memory access representing the specified memory operation with the specified value at
/// the specified clock cycle.
#[derive(Copy, Debug, Clone)]
pub struct MemorySegmentAccess {
    clk: Felt,
    op: MemoryOperation,
    value: Word,
}

impl MemorySegmentAccess {
    fn new(clk: Felt, op: MemoryOperation, value: Word) -> Self {
        Self { clk, op, value }
    }

    /// Returns the clock cycle at which this memory access happened.
    pub(super) fn clk(&self) -> Felt {
        self.clk
    }

    /// Returns the selector values matching the operation used in this memory access.
    pub(super) fn op_selectors(&self) -> Selectors {
        match self.op {
            MemoryOperation::InitRead => MEMORY_INIT_READ,
            MemoryOperation::CopyRead => MEMORY_COPY_READ,
            MemoryOperation::Write => MEMORY_WRITE,
        }
    }

    /// Returns the word value for this memory access.
    pub(super) fn value(&self) -> Word {
        self.value
    }
}
