use super::DebugCommand;
use miden_vm::{
    math::Felt, DefaultHost, MemAdviceProvider, Program, StackInputs, VmState, VmStateIterator,
};
use processor::MemMastForestStore;

/// Holds debugger state and iterator used for debugging.
pub struct DebugExecutor {
    vm_state_iter: VmStateIterator,
    vm_state: VmState,
}

impl DebugExecutor {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new DebugExecutor for the specified program, inputs and advice provider.
    ///
    /// # Errors
    /// Returns an error if the command cannot be parsed.
    pub fn new(
        program: Program,
        stack_inputs: StackInputs,
        advice_provider: MemAdviceProvider,
    ) -> Result<Self, String> {
        let mut vm_state_iter = processor::execute_iter(
            &program,
            stack_inputs,
            DefaultHost::new(advice_provider, MemMastForestStore::default()),
        );
        let vm_state = vm_state_iter
            .next()
            .ok_or(format!(
                "Failed to instantiate DebugExecutor - `VmStateIterator` is not yielding!"
            ))?
            .expect("initial state of vm must be healthy!");

        Ok(Self {
            vm_state_iter,
            vm_state,
        })
    }

    // MODIFIERS
    // --------------------------------------------------------------------------------------------

    /// executes a debug command against the vm in it's current state.
    pub fn execute(&mut self, command: DebugCommand) -> bool {
        match command {
            DebugCommand::Continue => {
                while let Some(new_vm_state) = self.next_vm_state() {
                    self.vm_state = new_vm_state;
                    if self.should_break() {
                        break;
                    }
                }
                self.print_vm_state();
            }
            DebugCommand::Next(cycles) => {
                for _cycle in 0..cycles {
                    match self.next_vm_state() {
                        Some(next_vm_state) => {
                            self.vm_state = next_vm_state;
                            if self.should_break() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                self.print_vm_state();
            }
            DebugCommand::Rewind => {
                while let Some(new_vm_state) = self.vm_state_iter.back() {
                    self.vm_state = new_vm_state;
                }
                self.print_vm_state();
            }
            DebugCommand::Back(cycles) => {
                for _cycle in 0..cycles {
                    match self.vm_state_iter.back() {
                        Some(new_vm_state) => {
                            self.vm_state = new_vm_state;
                            if self.should_break() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                self.print_vm_state()
            }
            DebugCommand::PrintState => self.print_vm_state(),
            DebugCommand::PrintStack => self.print_stack(),
            DebugCommand::PrintStackItem(index) => self.print_stack_item(index),
            DebugCommand::PrintMem => self.print_memory(),
            DebugCommand::PrintMemAddress(address) => self.print_memory_entry(address),
            DebugCommand::Clock => println!("{}", self.vm_state.clk),
            DebugCommand::Help => Self::print_help(),
            DebugCommand::Quit => return false,
        }
        true
    }

    /// iterates to the next clock cycle.
    fn next_vm_state(&mut self) -> Option<VmState> {
        match self.vm_state_iter.next() {
            Some(next_vm_state_result) => match next_vm_state_result {
                Ok(vm_state) => Some(vm_state),
                Err(err) => {
                    println!("Execution error: {err:?}");
                    None
                }
            },
            None => {
                println!("Program execution complete.");
                None
            }
        }
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// print general VM state information.
    fn print_vm_state(&self) {
        println!("{}", self.vm_state)
    }

    /// print all stack items.
    pub fn print_stack(&self) {
        println!(
            "{}",
            self.vm_state
                .stack
                .iter()
                .enumerate()
                .map(|(i, f)| format!("[{i}] {f}"))
                .collect::<Vec<_>>()
                .join("\n"),
        )
    }

    /// print specified stack item.
    pub fn print_stack_item(&self, index: usize) {
        let len = self.vm_state.stack.len();
        println!("stack len {}", len);
        if index >= len {
            println!("stack index must be < {len}")
        } else {
            println!("[{index}] = {}", self.vm_state.stack[index])
        }
    }

    /// print all memory entries.
    pub fn print_memory(&self) {
        for (address, mem) in self.vm_state.memory.iter() {
            Self::print_memory_data(address, mem)
        }
    }

    /// print specified memory entry.
    pub fn print_memory_entry(&self, address: u64) {
        let entry = self.vm_state.memory.iter().find_map(|(addr, mem)| match address == *addr {
            true => Some(mem),
            false => None,
        });

        match entry {
            Some(mem) => Self::print_memory_data(&address, mem),
            None => println!("memory at address '{address}' not found"),
        }
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// print memory data.
    fn print_memory_data(address: &u64, memory: &[Felt]) {
        let mem_int = memory.iter().map(|&x| x.as_int()).collect::<Vec<_>>();
        println!("{address} {mem_int:?}");
    }

    /// print help message
    fn print_help() {
        let message = "---------------------------------------------------------------------\n\
            Miden Assembly Debug CLI\n\
            ---------------------------------------------------------------------\n\
            next               moves to the next clock cycle\n\
            next <c>           moves `c` clock cycles forward\n\
            continue           executes program until completion or failure\n\
            back               rewinds `1` clock cycles\n\
            back <c>           rewinds `c` clock cycles\n\
            rewind             rewinds program until beginning\n\
            print              displays the complete state of the virtual machine\n\
            print mem          displays the complete state of memory\n\
            print mem <i>      displays memory at address `i`\n\
            print stack        displays the complete state of the stack\n\
            print stack <i>    displays the stack element at index `i`\n\
            clock              displays the current clock cycle\n\
            quit               quits the debugger\n\
            help               displays this message\n\
            \n\
            The following mappings are also available:\n\
            n -> next\n\
            c -> continue\n\
            b -> back\n\
            r -> rewind\n\
            p -> print\n\
            m -> mem\n\
            s -> stack\n\
            l -> clock\n\
            q -> quit\n\
            h -> help\n\
            ? -> help";

        println!("{}", message);
    }

    /// Returns `true` if the current state should break.
    fn should_break(&self) -> bool {
        self.vm_state.asmop.as_ref().map(|asm| asm.should_break()).unwrap_or(false)
    }
}
