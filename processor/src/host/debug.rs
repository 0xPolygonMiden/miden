use alloc::vec::Vec;
use std::{print, println};

use miden_air::RowIndex;
use vm_core::{DebugOptions, Word};

use super::ProcessState;
use crate::system::ContextId;

// DEBUG HANDLER
// ================================================================================================

/// Prints the info about the VM state specified by the provided options to stdout.
pub fn print_debug_info(process: ProcessState, options: &DebugOptions) {
    let printer = Printer::new(process.clk(), process.ctx(), process.fmp());
    match options {
        DebugOptions::StackAll => {
            printer.print_vm_stack(process, None);
        },
        DebugOptions::StackTop(n) => {
            printer.print_vm_stack(process, Some(*n as usize));
        },
        DebugOptions::MemAll => {
            printer.print_mem_all(process);
        },
        DebugOptions::MemInterval(n, m) => {
            printer.print_mem_interval(process, *n, *m);
        },
        DebugOptions::LocalInterval(n, m, num_locals) => {
            printer.print_local_interval(process, (*n as u32, *m as u32), *num_locals as u32);
        },
    }
}

// HELPER FUNCTIONS
// ================================================================================================

struct Printer {
    clk: RowIndex,
    ctx: ContextId,
    fmp: u32,
}

impl Printer {
    fn new(clk: RowIndex, ctx: ContextId, fmp: u64) -> Self {
        Self { clk, ctx, fmp: fmp as u32 }
    }

    /// Prints the number of stack items specified by `n` if it is provided, otherwise prints
    /// the whole stack.
    fn print_vm_stack(&self, process: ProcessState, n: Option<usize>) {
        let stack = process.get_stack_state();

        // determine how many items to print out
        let num_items = core::cmp::min(stack.len(), n.unwrap_or(stack.len()));

        // print all items except for the last one
        println!("Stack state before step {}:", self.clk);
        for (i, element) in stack.iter().take(num_items - 1).enumerate() {
            println!("├── {i:>2}: {element}");
        }

        // print the last item, and in case the stack has more items, print the total number of
        // un-printed items
        let i = num_items - 1;
        if num_items == stack.len() {
            println!("└── {i:>2}: {}\n", stack[i]);
        } else {
            println!("├── {i:>2}: {}", stack[i]);
            println!("└── ({} more items)\n", stack.len() - num_items);
        }
    }

    /// Prints the whole memory state at the cycle `clk` in context `ctx`.
    fn print_mem_all(&self, process: ProcessState) {
        let mem = process.get_mem_state(self.ctx);
        let padding =
            mem.iter().fold(0, |max, value| word_elem_max_len(Some(value.1)).max(max)) as usize;

        println!("Memory state before step {} for the context {}:", self.clk, self.ctx);

        // print the main part of the memory (wihtout the last value)
        for (addr, value) in mem.iter().take(mem.len() - 1) {
            print_mem_address(*addr, Some(*value), false, false, padding);
        }

        // print the last memory value
        if let Some((addr, value)) = mem.last() {
            print_mem_address(*addr, Some(*value), true, false, padding);
        }
    }

    /// Prints memory values in the provided addresses interval.
    fn print_mem_interval(&self, process: ProcessState, n: u32, m: u32) {
        let mut mem_interval = Vec::new();
        for addr in n..m + 1 {
            mem_interval.push((addr, process.get_mem_value(self.ctx, addr)));
        }

        if n == m {
            println!(
                "Memory state before step {} for the context {} at address {}:",
                self.clk, self.ctx, n
            )
        } else {
            println!(
                "Memory state before step {} for the context {} in the interval [{}, {}]:",
                self.clk, self.ctx, n, m
            )
        };

        print_interval(mem_interval, false);
    }

    /// Prints locals in provided indexes interval.
    fn print_local_interval(&self, process: ProcessState, interval: (u32, u32), num_locals: u32) {
        let mut local_mem_interval = Vec::new();
        let local_memory_offset = self.fmp - num_locals + 1;

        // in case start index is 0 and end index is 2^16, we should print all available locals.
        let (start, end) = if interval.0 == 0 && interval.1 == u16::MAX as u32 {
            (0, num_locals - 1)
        } else {
            interval
        };
        for index in start..end + 1 {
            local_mem_interval
                .push((index, process.get_mem_value(self.ctx, index + local_memory_offset)))
        }

        if interval.0 == 0 && interval.1 == u16::MAX as u32 {
            println!("State of procedure locals before step {}:", self.clk)
        } else if interval.0 == interval.1 {
            println!("State of procedure local at index {} before step {}:", interval.0, self.clk,)
        } else {
            println!(
                "State of procedure locals [{}, {}] before step {}:",
                interval.0, interval.1, self.clk,
            )
        };

        print_interval(local_mem_interval, true);
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Prints the provided memory interval.
///
/// If `is_local` is true, the output addresses are formatted as decimal values, otherwise as hex
/// strings.
fn print_interval(mem_interval: Vec<(u32, Option<Word>)>, is_local: bool) {
    let padding =
        mem_interval.iter().fold(0, |max, value| word_elem_max_len(value.1).max(max)) as usize;

    // print the main part of the memory (wihtout the last value)
    for (addr, value) in mem_interval.iter().take(mem_interval.len() - 1) {
        print_mem_address(*addr, *value, false, is_local, padding)
    }

    // print the last memory value
    if let Some((addr, value)) = mem_interval.last() {
        print_mem_address(*addr, *value, true, is_local, padding);
    }
}

/// Prints single memory value with its address.
///
/// If `is_local` is true, the output address is formatted as decimal value, otherwise as hex
/// string.
fn print_mem_address(
    addr: u32,
    value: Option<Word>,
    is_last: bool,
    is_local: bool,
    padding: usize,
) {
    if let Some(value) = value {
        if is_last {
            if is_local {
                print!("└── {addr:>5}: ");
            } else {
                print!("└── {addr:#010x}: ");
            }
            print_word(value, padding);
            println!();
        } else {
            if is_local {
                print!("├── {addr:>5}: ");
            } else {
                print!("├── {addr:#010x}: ");
            }
            print_word(value, padding);
        }
    } else if is_last {
        if is_local {
            println!("└── {addr:>5}: EMPTY\n");
        } else {
            println!("└── {addr:#010x}: EMPTY\n");
        }
    } else if is_local {
        println!("├── {addr:>5}: EMPTY");
    } else {
        println!("├── {addr:#010x}: EMPTY");
    }
}

/// Prints the provided Word with specified padding.
fn print_word(value: Word, padding: usize) {
    println!(
        "[{:>width$}, {:>width$}, {:>width$}, {:>width$}]",
        value[0].as_int(),
        value[1].as_int(),
        value[2].as_int(),
        value[3].as_int(),
        width = padding
    )
}

/// Returns the maximum length among the word elements.
fn word_elem_max_len(word: Option<Word>) -> u32 {
    if let Some(word) = word {
        word.iter()
            .fold(0, |max, value| (value.as_int().checked_ilog10().unwrap_or(1) + 1).max(max))
    } else {
        0
    }
}
