use super::{ExecutionError, Felt, Operation, Process};
use crate::{AdviceProvider, Host, Word};

// INPUT / OUTPUT OPERATIONS
// ================================================================================================

impl Process {
    // CONSTANT INPUTS
    // --------------------------------------------------------------------------------------------

    /// Pushes the provided value onto the stack.
    ///
    /// The original stack is shifted to the right by one item.
    pub(super) fn op_push(&mut self, value: Felt) -> Result<(), ExecutionError> {
        self.stack.set(0, value);
        self.stack.shift_right(0);
        Ok(())
    }

    // MEMORY READING AND WRITING
    // --------------------------------------------------------------------------------------------

    /// Loads a word (4 elements) from the specified memory address onto the stack.
    ///
    /// The operation works as follows:
    /// - The memory address is popped off the stack.
    /// - A word is retrieved from memory at the specified address. The memory is always initialized
    ///   to ZEROs, and thus, if the specified address has never been written to, four ZERO elements
    ///   are returned.
    /// - The top four elements of the stack are overwritten with values retrieved from memory.
    ///
    /// Thus, the net result of the operation is that the stack is shifted left by one item.
    pub(super) fn op_mloadw(&mut self) -> Result<(), ExecutionError> {
        // get the address from the stack and read the word from current memory context
        let mut word = self.read_mem_word(self.stack.get(0))?;
        word.reverse();

        // update the stack state
        for (i, &value) in word.iter().enumerate() {
            self.stack.set(i, value);
        }
        self.stack.shift_left(5);

        Ok(())
    }

    /// Loads the first element from the specified memory address onto the stack.
    ///
    /// The operation works as follows:
    /// - The memory address is popped off the stack.
    /// - A word is retrieved from memory at the specified address. The memory is always initialized
    ///   to ZEROs, and thus, if the specified address has never been written to, four ZERO elements
    ///   are returned.
    /// - The first element of the word retrieved from memory is pushed to the top of the stack.
    ///
    /// The first 3 helper registers are filled with the elements of the word which were not pushed
    /// to the stack. They are stored in stack order, with the last element of the word in helper
    /// register 0.
    pub(super) fn op_mload(&mut self) -> Result<(), ExecutionError> {
        // get the address from the stack and read the word from memory
        let mut word = self.read_mem_word(self.stack.get(0))?;
        word.reverse();

        // update the stack state
        self.stack.set(0, word[3]);
        self.stack.copy_state(1);

        // write the 3 unused elements to the helpers so they're available for constraint evaluation
        self.decoder.set_user_op_helpers(Operation::MLoad, &word[..3]);

        Ok(())
    }

    /// Loads two words from memory and replaces the top 8 elements of the stack with their
    /// contents.
    ///
    /// The operation works as follows:
    /// - The memory address of the first word is retrieved from 13th stack element (position 12).
    /// - Two consecutive words, starting at this address, are loaded from memory.
    /// - Elements of these words are written to the top 8 elements of the stack (element-wise, in
    ///   stack order).
    /// - Memory address (in position 12) is incremented by 2.
    /// - All other stack elements remain the same.
    pub(super) fn op_mstream(&mut self) -> Result<(), ExecutionError> {
        // get the address from position 12 on the stack
        let ctx = self.system.ctx();
        let addr = Self::get_valid_address(self.stack.get(12))?;

        // load two words from memory
        let words = self.chiplets.read_mem_double(ctx, addr)?;

        // replace the stack elements with the elements from memory (in stack order)
        for (i, &mem_value) in words.iter().flat_map(|word| word.iter()).rev().enumerate() {
            self.stack.set(i, mem_value);
        }

        // copy over the next 4 elements
        for i in 8..12 {
            let stack_value = self.stack.get(i);
            self.stack.set(i, stack_value);
        }

        // increment the address by 2
        self.stack.set(12, Felt::from(addr + 2));

        // copy over the rest of the stack
        self.stack.copy_state(13);

        Ok(())
    }

    /// Stores a word (4 elements) from the stack into the specified memory address.
    ///
    /// The operation works as follows:
    /// - The memory address is popped off the stack.
    /// - The top four stack items are saved into the specified memory address. The items are not
    ///   removed from the stack.
    ///
    /// Thus, the net result of the operation is that the stack is shifted left by one item.
    pub(super) fn op_mstorew(&mut self) -> Result<(), ExecutionError> {
        // get the address from the stack and build the word to be saved from the stack values
        let ctx = self.system.ctx();
        let addr = Self::get_valid_address(self.stack.get(0))?;

        // build the word in memory order (reverse of stack order)
        let word = [self.stack.get(4), self.stack.get(3), self.stack.get(2), self.stack.get(1)];

        // write the word to memory and get the previous word
        self.chiplets.write_mem(ctx, addr, word)?;

        // reverse the order of the memory word & update the stack state
        for (i, &value) in word.iter().rev().enumerate() {
            self.stack.set(i, value);
        }
        self.stack.shift_left(5);

        Ok(())
    }

    /// Stores an element from the stack into the first slot at the specified memory address.
    ///
    /// The operation works as follows:
    /// - The memory address is popped off the stack.
    /// - The top stack element is saved into the first element of the word located at the specified
    ///   memory address. The remaining 3 elements of the word are not affected. The element is not
    ///   removed from the stack.
    ///
    /// Thus, the net result of the operation is that the stack is shifted left by one item.
    ///
    /// The first 3 helper registers are filled with the remaining elements of the word which were
    /// previously stored in memory and not overwritten by the operation. They are stored in stack
    /// order, with the last element at helper register 0.
    pub(super) fn op_mstore(&mut self) -> Result<(), ExecutionError> {
        // get the address and the value from the stack
        let ctx = self.system.ctx();
        let addr = Self::get_valid_address(self.stack.get(0))?;
        let value = self.stack.get(1);

        // write the value to the memory and get the previous word
        let mut old_word = self.chiplets.write_mem_element(ctx, addr, value)?;
        // put the retrieved word into stack order
        old_word.reverse();

        // write the 3 unused elements to the helpers so they're available for constraint evaluation
        self.decoder.set_user_op_helpers(Operation::MStore, &old_word[..3]);

        // update the stack state
        self.stack.shift_left(1);

        Ok(())
    }

    /// Moves 8 elements from the advice stack to the memory, via the operand stack.
    ///
    /// The operation works as follows:
    /// - Two words are popped from the top of the advice stack.
    /// - The destination memory address for the first word is retrieved from the 13th stack element
    ///   (position 12).
    /// - The two words are written to memory consecutively, starting at this address.
    /// - These words replace the top 8 elements of the stack (element-wise, in stack order).
    /// - Memory address (in position 12) is incremented by 2.
    /// - All other stack elements remain the same.
    pub(super) fn op_pipe(&mut self, host: &mut impl Host) -> Result<(), ExecutionError> {
        // get the address from position 12 on the stack
        let ctx = self.system.ctx();
        let addr = Self::get_valid_address(self.stack.get(12))?;

        // pop two words from the advice stack
        let words = host.advice_provider_mut().pop_stack_dword(self.into())?;

        // write the words memory
        self.chiplets.write_mem_double(ctx, addr, words)?;

        // replace the elements on the stack with the word elements (in stack order)
        for (i, &adv_value) in words.iter().flat_map(|word| word.iter()).rev().enumerate() {
            self.stack.set(i, adv_value);
        }

        // copy over the next 4 elements
        for i in 8..12 {
            let stack_value = self.stack.get(i);
            self.stack.set(i, stack_value);
        }

        // increment the address by 2
        self.stack.set(12, Felt::from(addr + 2));

        // copy over the rest of the stack
        self.stack.copy_state(13);

        Ok(())
    }

    // ADVICE INPUTS
    // --------------------------------------------------------------------------------------------

    /// Pops an element from the advice stack and pushes it onto the operand stack.
    ///
    /// # Errors
    /// Returns an error if the advice stack is empty.
    pub(super) fn op_advpop(&mut self, host: &mut impl Host) -> Result<(), ExecutionError> {
        let value = host.advice_provider_mut().pop_stack(self.into())?;
        self.stack.set(0, value);
        self.stack.shift_right(0);
        Ok(())
    }

    /// Pops a word (4 elements) from the advice stack and overwrites the top word on the operand
    /// stack with it.
    ///
    /// # Errors
    /// Returns an error if the advice stack contains fewer than four elements.
    pub(super) fn op_advpopw(&mut self, host: &mut impl Host) -> Result<(), ExecutionError> {
        let word: Word = host.advice_provider_mut().pop_stack_word(self.into())?;

        self.stack.set(0, word[3]);
        self.stack.set(1, word[2]);
        self.stack.set(2, word[1]);
        self.stack.set(3, word[0]);
        self.stack.copy_state(4);

        Ok(())
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Returns the memory word at address `addr` in the current context.
    pub(crate) fn read_mem_word(&mut self, addr: Felt) -> Result<Word, ExecutionError> {
        let ctx = self.system.ctx();
        let mem_addr = Self::get_valid_address(addr)?;
        let word_at_addr = self.chiplets.read_mem(ctx, mem_addr)?;

        Ok(word_at_addr)
    }

    /// Checks that provided address is less than u32::MAX and returns it cast to u32.
    ///
    /// # Errors
    /// Returns an error if the provided address is greater than u32::MAX.
    fn get_valid_address(addr: Felt) -> Result<u32, ExecutionError> {
        let addr = addr.as_int();
        if addr > u32::MAX as u64 {
            return Err(ExecutionError::MemoryAddressOutOfBounds(addr));
        }
        Ok(addr as u32)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use vm_core::{utils::ToElements, Word, ONE, ZERO};

    use super::{
        super::{super::AdviceProvider, Operation, MIN_STACK_DEPTH},
        Felt, Host, Process,
    };
    use crate::{AdviceSource, ContextId, DefaultHost};

    #[test]
    fn op_push() {
        let mut host = DefaultHost::default();
        let mut process = Process::new_dummy_with_empty_stack();
        assert_eq!(MIN_STACK_DEPTH, process.stack.depth());
        assert_eq!(1, process.stack.current_clk());
        assert_eq!([ZERO; 16], process.stack.trace_state());

        // push one item onto the stack
        let op = Operation::Push(ONE);
        process.execute_op(op, &mut host).unwrap();
        let mut expected = [ZERO; 16];
        expected[0] = ONE;

        assert_eq!(MIN_STACK_DEPTH + 1, process.stack.depth());
        assert_eq!(2, process.stack.current_clk());
        assert_eq!(expected, process.stack.trace_state());

        // push another item onto the stack
        let op = Operation::Push(Felt::new(3));
        process.execute_op(op, &mut host).unwrap();
        let mut expected = [ZERO; 16];
        expected[0] = Felt::new(3);
        expected[1] = ONE;

        assert_eq!(MIN_STACK_DEPTH + 2, process.stack.depth());
        assert_eq!(3, process.stack.current_clk());
        assert_eq!(expected, process.stack.trace_state());
    }

    // MEMORY OPERATION TESTS
    // --------------------------------------------------------------------------------------------
    #[test]
    fn op_mloadw() {
        let mut host = DefaultHost::default();
        let mut process = Process::new_dummy_with_decoder_helpers_and_empty_stack();
        assert_eq!(0, process.chiplets.get_mem_size());

        // push a word onto the stack and save it at address 1
        let word = [1, 3, 5, 7].to_elements().try_into().unwrap();
        store_value(&mut process, 1, word, &mut host);

        // push four zeros onto the stack
        for _ in 0..4 {
            process.execute_op(Operation::Pad, &mut host).unwrap();
        }

        // push the address onto the stack and load the word
        process.execute_op(Operation::Push(ONE), &mut host).unwrap();
        process.execute_op(Operation::MLoadW, &mut host).unwrap();

        let expected_stack = build_expected_stack(&[7, 5, 3, 1, 7, 5, 3, 1]);
        assert_eq!(expected_stack, process.stack.trace_state());

        // check memory state
        assert_eq!(1, process.chiplets.get_mem_size());
        assert_eq!(word, process.chiplets.get_mem_value(ContextId::root(), 1).unwrap());

        // --- calling MLOADW with address greater than u32::MAX leads to an error ----------------
        process.execute_op(Operation::Push(Felt::new(u64::MAX / 2)), &mut host).unwrap();
        assert!(process.execute_op(Operation::MLoadW, &mut host).is_err());

        // --- calling MLOADW with a stack of minimum depth is ok ----------------
        let mut process = Process::new_dummy_with_decoder_helpers_and_empty_stack();
        assert!(process.execute_op(Operation::MLoadW, &mut host).is_ok());
    }

    #[test]
    fn op_mload() {
        let mut host = DefaultHost::default();
        let mut process = Process::new_dummy_with_decoder_helpers_and_empty_stack();
        assert_eq!(0, process.chiplets.get_mem_size());

        // push a word onto the stack and save it at address 2
        let word = [1, 3, 5, 7].to_elements().try_into().unwrap();
        store_value(&mut process, 2, word, &mut host);

        // push the address onto the stack and load the element
        process.execute_op(Operation::Push(Felt::new(2)), &mut host).unwrap();
        process.execute_op(Operation::MLoad, &mut host).unwrap();

        let expected_stack = build_expected_stack(&[1, 7, 5, 3, 1]);
        assert_eq!(expected_stack, process.stack.trace_state());

        // check memory state
        assert_eq!(1, process.chiplets.get_mem_size());
        assert_eq!(word, process.chiplets.get_mem_value(ContextId::root(), 2).unwrap());

        // --- calling MLOAD with address greater than u32::MAX leads to an error -----------------
        process.execute_op(Operation::Push(Felt::new(u64::MAX / 2)), &mut host).unwrap();
        assert!(process.execute_op(Operation::MLoad, &mut host).is_err());

        // --- calling MLOAD with a stack of minimum depth is ok ----------------
        let mut process = Process::new_dummy_with_decoder_helpers_and_empty_stack();
        assert!(process.execute_op(Operation::MLoad, &mut host).is_ok());
    }

    #[test]
    fn op_mstream() {
        let mut host = DefaultHost::default();
        let mut process = Process::new_dummy_with_decoder_helpers_and_empty_stack();

        // save two words into memory addresses 1 and 2
        let word1 = [30, 29, 28, 27];
        let word2 = [26, 25, 24, 23];
        let word1_felts: Word = word1.to_elements().try_into().unwrap();
        let word2_felts: Word = word2.to_elements().try_into().unwrap();
        store_value(&mut process, 1, word1_felts, &mut host);
        store_value(&mut process, 2, word2_felts, &mut host);

        // check memory state
        assert_eq!(2, process.chiplets.get_mem_size());
        assert_eq!(word1_felts, process.chiplets.get_mem_value(ContextId::root(), 1).unwrap());
        assert_eq!(word2_felts, process.chiplets.get_mem_value(ContextId::root(), 2).unwrap());

        // clear the stack
        for _ in 0..8 {
            process.execute_op(Operation::Drop, &mut host).unwrap();
        }

        // arrange the stack such that:
        // - 101 is at position 13 (to make sure it is not overwritten)
        // - 1 (the address) is at position 12
        // - values 1 - 12 are at positions 0 - 11. Adding the first 8 of these values to the values
        //   stored in memory should result in 35.
        process.execute_op(Operation::Push(Felt::new(101)), &mut host).unwrap();
        process.execute_op(Operation::Push(ONE), &mut host).unwrap();
        for i in 1..13 {
            process.execute_op(Operation::Push(Felt::new(i)), &mut host).unwrap();
        }

        // execute the MSTREAM operation
        process.execute_op(Operation::MStream, &mut host).unwrap();

        // the first 8 values should contain the values from memory. the next 4 values should remain
        // unchanged, and the address should be incremented by 2 (i.e., 1 -> 3).
        let stack_values = [
            word2[3], word2[2], word2[1], word2[0], word1[3], word1[2], word1[1], word1[0], 4, 3,
            2, 1, 3, 101,
        ];
        let expected_stack = build_expected_stack(&stack_values);
        assert_eq!(expected_stack, process.stack.trace_state());
    }

    #[test]
    fn op_mstorew() {
        let mut host = DefaultHost::default();
        let mut process = Process::new_dummy_with_decoder_helpers_and_empty_stack();
        assert_eq!(0, process.chiplets.get_mem_size());

        // push the first word onto the stack and save it at address 0
        let word1 = [1, 3, 5, 7].to_elements().try_into().unwrap();
        store_value(&mut process, 0, word1, &mut host);

        // check stack state
        let expected_stack = build_expected_stack(&[7, 5, 3, 1]);
        assert_eq!(expected_stack, process.stack.trace_state());

        // check memory state
        assert_eq!(1, process.chiplets.get_mem_size());
        assert_eq!(word1, process.chiplets.get_mem_value(ContextId::root(), 0).unwrap());

        // push the second word onto the stack and save it at address 3
        let word2 = [2, 4, 6, 8].to_elements().try_into().unwrap();
        store_value(&mut process, 3, word2, &mut host);

        // check stack state
        let expected_stack = build_expected_stack(&[8, 6, 4, 2, 7, 5, 3, 1]);
        assert_eq!(expected_stack, process.stack.trace_state());

        // check memory state
        assert_eq!(2, process.chiplets.get_mem_size());
        assert_eq!(word1, process.chiplets.get_mem_value(ContextId::root(), 0).unwrap());
        assert_eq!(word2, process.chiplets.get_mem_value(ContextId::root(), 3).unwrap());

        // --- calling MSTOREW with address greater than u32::MAX leads to an error ----------------
        process.execute_op(Operation::Push(Felt::new(u64::MAX / 2)), &mut host).unwrap();
        assert!(process.execute_op(Operation::MStoreW, &mut host).is_err());

        // --- calling STOREW with a stack of minimum depth is ok ----------------
        let mut process = Process::new_dummy_with_decoder_helpers_and_empty_stack();
        assert!(process.execute_op(Operation::MStoreW, &mut host).is_ok());
    }

    #[test]
    fn op_mstore() {
        let mut host = DefaultHost::default();
        let mut process = Process::new_dummy_with_decoder_helpers_and_empty_stack();
        assert_eq!(0, process.chiplets.get_mem_size());

        // push new element onto the stack and save it as first element of the word on
        // uninitialized memory at address 0
        let element = Felt::new(10);
        store_element(&mut process, 0, element, &mut host);

        // check stack state
        let expected_stack = build_expected_stack(&[10]);
        assert_eq!(expected_stack, process.stack.trace_state());

        // check memory state
        let mem_0 = [element, ZERO, ZERO, ZERO];
        assert_eq!(1, process.chiplets.get_mem_size());
        assert_eq!(mem_0, process.chiplets.get_mem_value(ContextId::root(), 0).unwrap());

        // push the word onto the stack and save it at address 2
        let word_2 = [1, 3, 5, 7].to_elements().try_into().unwrap();
        store_value(&mut process, 2, word_2, &mut host);

        // push new element onto the stack and save it as first element of the word at address 2
        let element = Felt::new(12);
        store_element(&mut process, 2, element, &mut host);

        // check stack state
        let expected_stack = build_expected_stack(&[12, 7, 5, 3, 1, 10]);
        assert_eq!(expected_stack, process.stack.trace_state());

        // check memory state to make sure the other 3 elements were not affected
        let mem_2 = [element, Felt::new(3), Felt::new(5), Felt::new(7)];
        assert_eq!(2, process.chiplets.get_mem_size());
        assert_eq!(mem_2, process.chiplets.get_mem_value(ContextId::root(), 2).unwrap());

        // --- calling MSTORE with address greater than u32::MAX leads to an error ----------------
        process.execute_op(Operation::Push(Felt::new(u64::MAX / 2)), &mut host).unwrap();
        assert!(process.execute_op(Operation::MStore, &mut host).is_err());

        // --- calling MSTORE with a stack of minimum depth is ok ----------------
        let mut process = Process::new_dummy_with_decoder_helpers_and_empty_stack();
        assert!(process.execute_op(Operation::MStore, &mut host).is_ok());
    }

    #[test]
    fn op_pipe() {
        let mut host = DefaultHost::default();
        let mut process = Process::new_dummy_with_decoder_helpers_and_empty_stack();

        // push words onto the advice stack
        let word1 = [30, 29, 28, 27];
        let word2 = [26, 25, 24, 23];
        let word1_felts: Word = word1.to_elements().try_into().unwrap();
        let word2_felts: Word = word2.to_elements().try_into().unwrap();
        for element in word2_felts.iter().rev().chain(word1_felts.iter().rev()).copied() {
            // reverse the word order, since elements are pushed onto the advice stack.
            host.advice_provider_mut().push_stack(AdviceSource::Value(element)).unwrap();
        }

        // arrange the stack such that:
        // - 101 is at position 13 (to make sure it is not overwritten)
        // - 1 (the address) is at position 12
        // - values 1 - 12 are at positions 0 - 11. Replacing the first 8 of these values with the
        //   values from the advice stack should result in 30 through 23 in stack order (with 23 at
        //   stack[0]).
        process.execute_op(Operation::Push(Felt::new(101)), &mut host).unwrap();
        process.execute_op(Operation::Push(ONE), &mut host).unwrap();
        for i in 1..13 {
            process.execute_op(Operation::Push(Felt::new(i)), &mut host).unwrap();
        }

        // execute the PIPE operation
        process.execute_op(Operation::Pipe, &mut host).unwrap();

        // check memory state contains the words from the advice stack
        assert_eq!(2, process.chiplets.get_mem_size());
        assert_eq!(word1_felts, process.chiplets.get_mem_value(ContextId::root(), 1).unwrap());
        assert_eq!(word2_felts, process.chiplets.get_mem_value(ContextId::root(), 2).unwrap());

        // the first 8 values should be the values from the advice stack. the next 4 values should
        // remain unchanged, and the address should be incremented by 2 (i.e., 1 -> 3).
        let stack_values = [
            word2[3], word2[2], word2[1], word2[0], word1[3], word1[2], word1[1], word1[0], 4, 3,
            2, 1, 3, 101,
        ];
        let expected_stack = build_expected_stack(&stack_values);
        assert_eq!(expected_stack, process.stack.trace_state());
    }

    // ADVICE INPUT TESTS
    // --------------------------------------------------------------------------------------------

    #[test]
    fn op_advpop() {
        // popping from the advice stack should push the value onto the operand stack
        let (mut process, mut host) = Process::new_dummy_with_advice_stack(&[3]);
        process.execute_op(Operation::Push(ONE), &mut host).unwrap();
        process.execute_op(Operation::AdvPop, &mut host).unwrap();
        let expected = build_expected_stack(&[3, 1]);
        assert_eq!(expected, process.stack.trace_state());

        // popping again should result in an error because advice stack is empty
        assert!(process.execute_op(Operation::AdvPop, &mut host).is_err());
    }

    #[test]
    fn op_advpopw() {
        // popping a word from the advice stack should overwrite top 4 elements of the operand
        // stack
        let (mut process, mut host) = Process::new_dummy_with_advice_stack(&[3, 4, 5, 6]);
        process.execute_op(Operation::Push(ONE), &mut host).unwrap();
        process.execute_op(Operation::Pad, &mut host).unwrap();
        process.execute_op(Operation::Pad, &mut host).unwrap();
        process.execute_op(Operation::Pad, &mut host).unwrap();
        process.execute_op(Operation::Pad, &mut host).unwrap();
        process.execute_op(Operation::AdvPopW, &mut host).unwrap();
        let expected = build_expected_stack(&[6, 5, 4, 3, 1]);
        assert_eq!(expected, process.stack.trace_state());
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    fn store_value<H>(process: &mut Process, addr: u64, value: [Felt; 4], host: &mut H)
    where
        H: Host,
    {
        for &value in value.iter() {
            process.execute_op(Operation::Push(value), host).unwrap();
        }
        let addr = Felt::new(addr);
        process.execute_op(Operation::Push(addr), host).unwrap();
        process.execute_op(Operation::MStoreW, host).unwrap();
    }

    fn store_element<H>(process: &mut Process, addr: u64, value: Felt, host: &mut H)
    where
        H: Host,
    {
        process.execute_op(Operation::Push(value), host).unwrap();
        let addr = Felt::new(addr);
        process.execute_op(Operation::Push(addr), host).unwrap();
        process.execute_op(Operation::MStore, host).unwrap();
    }

    fn build_expected_stack(values: &[u64]) -> [Felt; 16] {
        let mut expected = [ZERO; 16];
        for (&value, result) in values.iter().zip(expected.iter_mut()) {
            *result = Felt::new(value);
        }
        expected
    }
}
