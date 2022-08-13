use super::{BTreeMap, Felt, FieldElement, Vec};
use crate::RangeCheckTrace;
use vm_core::utils::uninit_vector;

mod aux_trace;
pub use aux_trace::AuxTraceBuilder;

mod request;
use request::CycleRangeChecks;

#[cfg(test)]
mod tests;

// RANGE CHECKER
// ================================================================================================

/// Range checker for the VM.
///
/// This component is responsible for building an execution trace for all 16-bit range checks
/// performed by the VM. Thus, the [RangeChecker] doesn't actually check if a given value fits
/// into 16-bits, but rather keeps track of all 16-bit range checks performed by the VM.
///
/// ## Execution trace
/// Execution trace generated by the range checker consists of 4 columns. Conceptually, the table
/// is split into two sets of rows (two segments): an 8-bit segment and a 16-bit segment. The
/// 8-bit segment must enumerate all 256 possible 8-bit values. Values must be in increasing order,
/// but duplicates are allowed. The 16-bit segment must start with value 0 and end with value
/// 65535. The values must also be in increasing order but can be up to 255 values apart, and
/// duplicates are also allowed.
///
/// The general idea is that we use the 8-bit portion of the table to range-check the "breaks"
/// in between values for the 16-bit portion of the table. Given these constraints, the minimum
/// trace length required to support even a few range checks is 1024. However, with a table of
/// 1024 rows we can support close to 600 16-bit range checks (assuming the checked values are
/// randomly distributed).
///
/// The layout illustrated below.
///
///    t     s0     s1     v  
/// ├─────┴──────┴──────┴─────┤
///
/// In the above, the meaning of the columns is as follows:
/// - Column `t` defines which segment of the table we are in. When t = 0, we are in the 8-bit
///   segment of the table, and when t = 1, we are in the 16-bit segment of the table. Values in
///   this column start with zeros and can switch to ones only once.
/// - Column `v` contains the value being range-checked. When t = 0, v must be an 8-bit value, and
///   when t = 1, v must be a 16-bit value.
/// - Column `s0` and `s1` specify how many lookups are to be included for a given value.
///   Specifically: (0, 0) means no lookups, (1, 0) means one lookup, (0, 1), means two lookups,
///   and (1, 1) means four lookups.
///
/// Thus, for example, if a value was range-checked just once, we'll need to add a single row to
/// the table with (t, s0, s1, v) set to (1, 1, 0, v), where v is the value.
///
/// If, on the other hand, the value was range-checked 5 times, we'll need two rows in the table:
/// (1, 1, 1, v) and (1, 1, 0, v). The first row specifies that there was 4 lookups and the second
/// row add the fifth lookup.
#[allow(dead_code)]
pub struct RangeChecker {
    /// Tracks lookup count for each checked value.
    lookups: BTreeMap<u16, usize>,
    // Range check lookups performed by all user operations, grouped and sorted by clock cycle. Each
    // cycle is mapped to a single CycleRangeChecks instance which includes lookups from the stack,
    // memory, or both.
    cycle_range_checks: BTreeMap<usize, CycleRangeChecks>,
}

#[allow(dead_code)]
impl RangeChecker {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new [RangeChecker] instantiated with an empty lookup table.
    pub fn new() -> Self {
        let mut lookups = BTreeMap::new();
        // we need to make sure that the first and the last row of the 16-bit segment of the table
        // are initialized. this simplifies trace table building later on.
        lookups.insert(0, 0);
        lookups.insert(u16::MAX, 0);
        Self {
            lookups,
            cycle_range_checks: BTreeMap::new(),
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns length of execution trace required to describe all 16-bit range checks performed
    /// by the VM.
    pub fn trace_len(&self) -> usize {
        let (lookups_8bit, num_16bit_rows) = self.build_8bit_lookup();
        let num_8bit_rows = get_num_8bit_rows(&lookups_8bit);
        num_8bit_rows + num_16bit_rows
    }

    // TRACE MUTATORS
    // --------------------------------------------------------------------------------------------
    /// Adds the specified value to the trace of this range checker's lookups.
    pub fn add_value(&mut self, value: u16) {
        self.lookups
            .entry(value as u16)
            .and_modify(|v| *v += 1)
            .or_insert(1);
    }

    /// Adds range check lookups from the [Stack] to this [RangeChecker] instance. Stack lookups are
    /// guaranteed to be added at unique clock cycles, since operations are sequential and no range
    /// check lookups are added before or during the stack operation processing.
    pub fn add_stack_checks(&mut self, clk: usize, values: &[u16; 4]) {
        self.add_value(values[0]);
        self.add_value(values[1]);
        self.add_value(values[2]);
        self.add_value(values[3]);

        // Stack operations are added before memory operations at unique clock cycles.
        self.cycle_range_checks
            .insert(clk, CycleRangeChecks::new_from_stack(values));
    }

    /// Adds range check lookups from [Memory] to this [RangeChecker] instance. Memory lookups are
    /// always added after all stack lookups have completed, since they are processed during trace
    /// finalization.
    pub fn add_mem_checks(&mut self, clk: usize, values: &[u16; 2]) {
        self.add_value(values[0]);
        self.add_value(values[1]);

        self.cycle_range_checks
            .entry(clk)
            .and_modify(|entry| entry.add_memory_checks(values))
            .or_insert_with(|| CycleRangeChecks::new_from_memory(values));
    }

    // EXECUTION TRACE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Converts this [RangeChecker] into an execution trace with 4 columns and the number of rows
    /// specified by the `target_len` parameter.
    ///
    /// If the number of rows need to represent execution trace of this range checker is smaller
    /// than `target_len` parameter, the trace is padded with extra rows.
    ///
    /// `num_rand_rows` indicates the number of rows at the end of the trace which will be
    /// overwritten with random values. Values in these rows are not initialized.
    ///
    /// # Panics
    /// Panics if `target_len` is not a power of two or is smaller than the trace length needed
    /// to represent all lookups in this range checker.
    pub fn into_trace(self, target_len: usize, num_rand_rows: usize) -> RangeCheckTrace {
        assert!(
            target_len.is_power_of_two(),
            "target trace length is not a power of two"
        );

        // determine the length of the trace required to support all the lookups in this range
        // checker, and make sure this length is smaller than or equal to the target trace length,
        // accounting for rows with random values.
        //
        // we do the trace length computation here instead of using Self::trace_len() because we
        // need to use lookups_8bit table later in this function, and we don't want to create it
        // twice.
        let (lookups_8bit, num_16_bit_rows) = self.build_8bit_lookup();
        let num_8bit_rows = get_num_8bit_rows(&lookups_8bit);
        let trace_len = num_8bit_rows + num_16_bit_rows;
        assert!(
            trace_len + num_rand_rows <= target_len,
            "target trace length too small"
        );

        // allocated memory for the trace; this memory is un-initialized but this is not a problem
        // because we'll overwrite all values in it anyway.
        let mut trace = unsafe {
            [
                uninit_vector(target_len),
                uninit_vector(target_len),
                uninit_vector(target_len),
                uninit_vector(target_len),
            ]
        };
        // Allocate uninitialized memory for accumulating the precomputed auxiliary column hints.
        let mut row_flags = unsafe { uninit_vector(target_len) };

        // determine the number of padding rows needed to get to target trace length and pad the
        // table with the required number of rows.
        let num_padding_rows = target_len - trace_len - num_rand_rows;
        trace[1][..num_padding_rows].fill(Felt::ZERO);
        trace[2][..num_padding_rows].fill(Felt::ZERO);
        trace[3][..num_padding_rows].fill(Felt::ZERO);

        // Initialize the padded rows of the auxiliary column hints with the default flag, F0,
        // indicating s0 = s1 = ZERO.
        row_flags[..num_padding_rows].fill(RangeCheckFlag::F0);

        // build the 8-bit segment of the trace table
        let mut i = num_padding_rows;
        for (value, num_lookups) in lookups_8bit.into_iter().enumerate() {
            write_value(
                &mut trace,
                &mut i,
                num_lookups,
                value as u64,
                &mut row_flags,
            );
        }

        // fill in the first column to indicate where the 8-bit segment ends and where the
        // 16-bit segment begins
        trace[0][..i].fill(Felt::ZERO);
        trace[0][i..].fill(Felt::ONE);

        // build the 16-bit segment of the trace table
        let start_16bit = i;
        let mut prev_value = 0u16;
        for (&value, &num_lookups) in self.lookups.iter() {
            // when the delta between two values is greater than 255, insert "bridge" rows
            for value in (prev_value..value).step_by(255).skip(1) {
                write_value(&mut trace, &mut i, 0, value as u64, &mut row_flags);
            }
            write_value(
                &mut trace,
                &mut i,
                num_lookups,
                value as u64,
                &mut row_flags,
            );
            prev_value = value;
        }

        // pad the trace with an extra row of 0 lookups for u16::MAX so that when b_range is built
        // there is space for the inclusion of u16::MAX range check lookups before the trace ends.
        // (When there is data at the end of the main trace, auxiliary bus columns always need to be
        // one row longer than the main trace, since values in the bus column are based on data from
        // the "current" row of the main trace but placed into the "next" row of the bus column.)
        write_value(&mut trace, &mut i, 0, (u16::MAX).into(), &mut row_flags);

        RangeCheckTrace {
            trace,
            aux_builder: AuxTraceBuilder::new(self.cycle_range_checks, row_flags, start_16bit),
        }
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Builds an 8-bit lookup table required to support all 16-bit lookups currently in
    /// self.lookups, and returns this table together with the number of 16-bit table rows needed
    /// to support all 16-bit lookups.
    fn build_8bit_lookup(&self) -> ([usize; 256], usize) {
        let mut result = [0; 256];

        // pad the trace length by one, to account for an extra row of the u16::MAX value at the end
        // of the 16-bit segment of the trace, required for building the `b_range` column.
        let mut num_16bit_rows = 1;

        // add a lookup for ZERO to account for the extra row of the u16::MAX value
        result[0] = 1;

        let mut prev_value = 0u16;
        for (&value, &num_lookups) in self.lookups.iter() {
            // determine how many 16-bit lookup rows we need for this value; if the number of rows
            // is greater than 1, we also need 8-bit lookups for ZERO value since the delta between
            // rows of the same value is zero.
            let num_rows = lookups_to_rows(num_lookups);
            result[0] += num_rows - 1;
            num_16bit_rows += num_rows;

            // determine the delta between this and the previous value. we need to know this delta
            // to determine if we need to insert any "bridge" rows to the 16-bit portion of the the
            // table, this is needed since rows in the 16-bit portion of the table can be at most
            // 255 rows apart.
            let delta = value - prev_value;
            let (delta_q, delta_r) = div_rem(delta as usize, 255);

            if delta_q != 0 {
                result[255] += delta_q;
                let num_bridge_rows = if delta_r == 0 { delta_q - 1 } else { delta_q };
                num_16bit_rows += num_bridge_rows;
            }
            if delta_r != 0 {
                result[delta_r] += 1;
            }

            prev_value = value;
        }

        (result, num_16bit_rows)
    }
}

impl Default for RangeChecker {
    fn default() -> Self {
        Self::new()
    }
}

// RANGE CHECKER ROWS
// ================================================================================================

/// A precomputed hint value that can be used to help construct the execution trace for the
/// auxiliary columns p0 and p1 used for multiset checks. The hint is a precomputed flag value based
/// on the selectors s0 and s1 in the trace.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RangeCheckFlag {
    F0,
    F1,
    F2,
    F3,
}

impl RangeCheckFlag {
    /// Reduces this row to a single field element in the field specified by E. This requires
    /// at least 1 alpha value.
    pub fn to_value<E: FieldElement<BaseField = Felt>>(&self, value: Felt, alphas: &[E]) -> E {
        let alpha: E = alphas[0];

        match self {
            RangeCheckFlag::F0 => E::ONE,
            RangeCheckFlag::F1 => alpha + value.into(),
            RangeCheckFlag::F2 => (alpha + value.into()).square(),
            RangeCheckFlag::F3 => ((alpha + value.into()).square()).square(),
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns the number of rows needed to perform the specified number of lookups for an 8-bit
/// value. Note that even if the number of lookups is 0, at least one row is required. This is
/// because for an 8-bit table, rows must contain contiguous values.
///
/// The number of rows is determined as follows:
/// - First we compute the number of rows for 4 lookups per row.
/// - Then we compute the number of rows for 2 lookups per row.
/// - Then, we compute the number of rows for a single lookup per row.
///
/// The return value is the sum of these three values.
fn lookups_to_rows(num_lookups: usize) -> usize {
    if num_lookups == 0 {
        1
    } else {
        let (num_rows4, num_lookups) = div_rem(num_lookups, 4);
        let (num_rows2, num_rows1) = div_rem(num_lookups, 2);
        num_rows4 + num_rows2 + num_rows1
    }
}

/// Returns the number of trace rows needed to describe the specified 8-bit lookup table.
fn get_num_8bit_rows(lookups: &[usize; 256]) -> usize {
    let mut result = 0;
    for &num_lookups in lookups.iter() {
        result += lookups_to_rows(num_lookups);
    }
    result
}

/// Populates the trace with the rows needed to support the specified number of lookups against
/// the specified value.
fn write_value(
    trace: &mut [Vec<Felt>],
    step: &mut usize,
    num_lookups: usize,
    value: u64,
    row_flags: &mut [RangeCheckFlag],
) {
    // if the number of lookups is 0, only one trace row is required
    if num_lookups == 0 {
        row_flags[*step] = RangeCheckFlag::F0;
        write_trace_row(trace, step, Felt::ZERO, Felt::ZERO, value as u64);
        return;
    }

    // write rows which can support 4 lookups per row
    let (num_rows, num_lookups) = div_rem(num_lookups, 4);
    for _ in 0..num_rows {
        row_flags[*step] = RangeCheckFlag::F3;
        write_trace_row(trace, step, Felt::ONE, Felt::ONE, value as u64);
    }

    // write rows which can support 2 lookups per row
    let (num_rows, num_lookups) = div_rem(num_lookups, 2);
    for _ in 0..num_rows {
        row_flags[*step] = RangeCheckFlag::F2;
        write_trace_row(trace, step, Felt::ZERO, Felt::ONE, value as u64);
    }

    // write rows which can support only one lookup per row
    for _ in 0..num_lookups {
        row_flags[*step] = RangeCheckFlag::F1;
        write_trace_row(trace, step, Felt::ONE, Felt::ZERO, value as u64);
    }
}

/// Populates a single row at the specified step in the trace table. This does not write values
/// into the first column of the trace (the segment identifier) because values into this
/// column are written in bulk.
fn write_trace_row(trace: &mut [Vec<Felt>], step: &mut usize, s0: Felt, s1: Felt, value: u64) {
    trace[1][*step] = s0;
    trace[2][*step] = s1;
    trace[3][*step] = Felt::new(value);
    *step += 1;
}

/// Returns quotient and remainder of dividing the provided value by the divisor.
fn div_rem(value: usize, divisor: usize) -> (usize, usize) {
    let q = value / divisor;
    let r = value % divisor;
    (q, r)
}
