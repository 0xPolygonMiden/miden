use alloc::vec::Vec;
use core::fmt;
use miden_formatting::prettier::PrettyPrint;

use miden_crypto::hash::rpo::RpoDigest;

use crate::mast::{DecoratorId, MastForest};

// EXTERNAL NODE
// ================================================================================================

/// Node for referencing procedures not present in a given [`MastForest`] (hence "external").
///
/// External nodes can be used to verify the integrity of a program's hash while keeping parts of
/// the program secret. They also allow a program to refer to a well-known procedure that was not
/// compiled with the program (e.g. a procedure in the standard library).
///
/// The hash of an external node is the hash of the procedure it represents, such that an external
/// node can be swapped with the actual subtree that it represents without changing the MAST root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalNode {
    digest: RpoDigest,
    before_enter: Vec<DecoratorId>,
    after_exit: Vec<DecoratorId>,
}

impl ExternalNode {
    /// Returns a new [`ExternalNode`] instantiated with the specified procedure hash.
    pub fn new(procedure_hash: RpoDigest) -> Self {
        Self {
            digest: procedure_hash,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
        }
    }
}

impl ExternalNode {
    /// Returns the commitment to the MAST node referenced by this external node.
    pub fn digest(&self) -> RpoDigest {
        self.digest
    }

    /// Returns the decorators to be executed before this node is executed.
    pub fn before_enter(&self) -> &[DecoratorId] {
        &self.before_enter
    }

    /// Returns the decorators to be executed after this node is executed.
    pub fn after_exit(&self) -> &[DecoratorId] {
        &self.after_exit
    }
}

/// Mutators
impl ExternalNode {
    /// Sets the list of decorators to be executed before this node.
    pub fn set_before_enter(&mut self, decorator_ids: Vec<DecoratorId>) {
        self.before_enter = decorator_ids;
    }

    /// Sets the list of decorators to be executed after this node.
    pub fn set_after_exit(&mut self, decorator_ids: Vec<DecoratorId>) {
        self.after_exit = decorator_ids;
    }
}

// PRETTY PRINTING
// ================================================================================================

impl ExternalNode {
    pub(super) fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> impl fmt::Display + 'a {
        ExternalNodePrettyPrint { external_node: self, mast_forest }
    }

    pub(super) fn to_pretty_print<'a>(
        &'a self,
        mast_forest: &'a MastForest,
    ) -> impl PrettyPrint + 'a {
        ExternalNodePrettyPrint { external_node: self, mast_forest }
    }
}

struct ExternalNodePrettyPrint<'a> {
    external_node: &'a ExternalNode,
    mast_forest: &'a MastForest,
}

impl<'a> crate::prettier::PrettyPrint for ExternalNodePrettyPrint<'a> {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;
        use miden_formatting::hex::ToHex;

        let pre_decorators = self
            .external_node
            .before_enter()
            .iter()
            .map(|&decorator_id| self.mast_forest[decorator_id].render())
            .reduce(|acc, doc| acc + const_text(" ") + doc)
            .unwrap_or_default();

        let post_decorators = self
            .external_node
            .after_exit()
            .iter()
            .map(|&decorator_id| self.mast_forest[decorator_id].render())
            .reduce(|acc, doc| acc + const_text(" ") + doc)
            .unwrap_or_default();

        pre_decorators
            + const_text("external")
            + const_text(".")
            + text(self.external_node.digest.as_bytes().to_hex_with_prefix())
            + post_decorators
    }
}

impl<'a> fmt::Display for ExternalNodePrettyPrint<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::prettier::PrettyPrint;
        self.pretty_print(f)
    }
}
