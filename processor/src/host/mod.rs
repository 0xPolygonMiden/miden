use alloc::sync::Arc;

use vm_core::{crypto::hash::RpoDigest, mast::MastForest, DebugOptions};

use super::{ExecutionError, ProcessState};
use crate::{KvMap, MemAdviceProvider};

pub(super) mod advice;
use advice::AdviceProvider;

#[cfg(feature = "std")]
mod debug;

mod mast_forest_store;
pub use mast_forest_store::{MastForestStore, MemMastForestStore};

// HOST TRAIT
// ================================================================================================

/// Defines an interface by which the VM can interact with the host.
///
/// There are four main categories of interactions between the VM and the host:
/// 1. accessing the advice provider,
/// 2. getting a library's MAST forest,
/// 3. handling advice events (which internally mutates the advice provider), and
/// 4. handling debug and trace events.
pub trait Host {
    type AdviceProvider: AdviceProvider;

    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the advice provider.
    fn advice_provider(&self) -> &Self::AdviceProvider;

    /// Returns a mutable reference to the advice provider.
    fn advice_provider_mut(&mut self) -> &mut Self::AdviceProvider;

    /// Returns MAST forest corresponding to the specified digest, or None if the MAST forest for
    /// this digest could not be found in this [Host].
    fn get_mast_forest(&self, node_digest: &RpoDigest) -> Option<Arc<MastForest>>;

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Handles the event emitted from the VM.
    fn on_event(&mut self, _process: ProcessState, _event_id: u32) -> Result<(), ExecutionError> {
        #[cfg(feature = "std")]
        std::println!(
            "Event with id {} emitted at step {} in context {}",
            _event_id,
            _process.clk(),
            _process.ctx()
        );
        Ok(())
    }

    /// Handles the debug request from the VM.
    fn on_debug(
        &mut self,
        _process: ProcessState,
        _options: &DebugOptions,
    ) -> Result<(), ExecutionError> {
        #[cfg(feature = "std")]
        debug::print_debug_info(_process, _options);
        Ok(())
    }

    /// Handles the trace emitted from the VM.
    fn on_trace(&mut self, _process: ProcessState, _trace_id: u32) -> Result<(), ExecutionError> {
        #[cfg(feature = "std")]
        std::println!(
            "Trace with id {} emitted at step {} in context {}",
            _trace_id,
            _process.clk(),
            _process.ctx()
        );
        Ok(())
    }

    /// Handles the failure of the assertion instruction.
    fn on_assert_failed(&mut self, process: ProcessState, err_code: u32) -> ExecutionError {
        ExecutionError::FailedAssertion {
            clk: process.clk(),
            err_code,
            err_msg: None,
        }
    }
}

impl<H> Host for &mut H
where
    H: Host,
{
    type AdviceProvider = H::AdviceProvider;

    fn advice_provider(&self) -> &Self::AdviceProvider {
        H::advice_provider(self)
    }

    fn advice_provider_mut(&mut self) -> &mut Self::AdviceProvider {
        H::advice_provider_mut(self)
    }

    fn get_mast_forest(&self, node_digest: &RpoDigest) -> Option<Arc<MastForest>> {
        H::get_mast_forest(self, node_digest)
    }

    fn on_debug(
        &mut self,
        process: ProcessState,
        options: &DebugOptions,
    ) -> Result<(), ExecutionError> {
        H::on_debug(self, process, options)
    }

    fn on_event(&mut self, process: ProcessState, event_id: u32) -> Result<(), ExecutionError> {
        H::on_event(self, process, event_id)
    }

    fn on_trace(&mut self, process: ProcessState, trace_id: u32) -> Result<(), ExecutionError> {
        H::on_trace(self, process, trace_id)
    }

    fn on_assert_failed(&mut self, process: ProcessState, err_code: u32) -> ExecutionError {
        H::on_assert_failed(self, process, err_code)
    }
}

// DEFAULT HOST IMPLEMENTATION
// ================================================================================================

/// A default [Host] implementation that provides the essential functionality required by the VM.
pub struct DefaultHost<A> {
    adv_provider: A,
    store: MemMastForestStore,
}

impl<A: Clone> Clone for DefaultHost<A> {
    fn clone(&self) -> Self {
        Self {
            adv_provider: self.adv_provider.clone(),
            store: self.store.clone(),
        }
    }
}

impl Default for DefaultHost<MemAdviceProvider> {
    fn default() -> Self {
        Self {
            adv_provider: MemAdviceProvider::default(),
            store: MemMastForestStore::default(),
        }
    }
}

impl<A> DefaultHost<A>
where
    A: AdviceProvider,
{
    pub fn new(adv_provider: A) -> Self {
        Self {
            adv_provider,
            store: MemMastForestStore::default(),
        }
    }

    pub fn load_mast_forest(&mut self, mast_forest: Arc<MastForest>) -> Result<(), ExecutionError> {
        // Load the MAST's advice data into the advice provider.

        for (digest, values) in mast_forest.advice_map().iter() {
            if let Some(stored_values) = self.advice_provider().get_mapped_values(digest) {
                if stored_values != values {
                    return Err(ExecutionError::AdviceMapKeyAlreadyPresent(digest.into()));
                }
            } else {
                self.advice_provider_mut().insert_into_map(digest.into(), values.clone());
            }
        }

        self.store.insert(mast_forest);
        Ok(())
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn advice_provider(&self) -> &A {
        &self.adv_provider
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn advice_provider_mut(&mut self) -> &mut A {
        &mut self.adv_provider
    }

    pub fn into_inner(self) -> A {
        self.adv_provider
    }
}

impl<A> Host for DefaultHost<A>
where
    A: AdviceProvider,
{
    type AdviceProvider = A;

    fn advice_provider(&self) -> &Self::AdviceProvider {
        &self.adv_provider
    }

    fn advice_provider_mut(&mut self) -> &mut Self::AdviceProvider {
        &mut self.adv_provider
    }

    fn get_mast_forest(&self, node_digest: &RpoDigest) -> Option<Arc<MastForest>> {
        self.store.get(node_digest)
    }
}
