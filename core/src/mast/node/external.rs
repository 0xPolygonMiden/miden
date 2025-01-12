use core::fmt;

use miden_crypto::hash::rpo::RpoDigest;
use miden_formatting::{
    hex::ToHex,
    prettier::{const_text, nl, text, Document, PrettyPrint},
};

use crate::mast::{DecoratorSpan, MastForest};

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
    before_enter: DecoratorSpan,
    after_exit: DecoratorSpan,
}

impl ExternalNode {
    /// Returns a new [`ExternalNode`] instantiated with the specified procedure hash.
    pub fn new(procedure_hash: RpoDigest) -> Self {
        Self {
            digest: procedure_hash,
            before_enter: DecoratorSpan::default(),
            after_exit: DecoratorSpan::default(),
        }
    }
}

impl ExternalNode {
    /// Returns the commitment to the MAST node referenced by this external node.
    pub fn digest(&self) -> RpoDigest {
        self.digest
    }

    /// Returns the decorators to be executed before this node is executed.
    pub fn before_enter(&self) -> &DecoratorSpan {
        &self.before_enter
    }

    /// Returns the decorators to be executed after this node is executed.
    pub fn after_exit(&self) -> &DecoratorSpan {
        &self.after_exit
    }
}

/// Mutators
impl ExternalNode {
    /// Sets the list of decorators to be executed before this node.
    pub fn set_before_enter(&mut self, decorator_ids: DecoratorSpan) {
        self.before_enter = decorator_ids;
    }

    /// Sets the list of decorators to be executed after this node.
    pub fn set_after_exit(&mut self, decorator_ids: DecoratorSpan) {
        self.after_exit = decorator_ids;
    }
}

// PRETTY PRINTING
// ================================================================================================

impl ExternalNode {
    pub(super) fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> impl fmt::Display + 'a {
        ExternalNodePrettyPrint { node: self, mast_forest }
    }

    pub(super) fn to_pretty_print<'a>(
        &'a self,
        mast_forest: &'a MastForest,
    ) -> impl PrettyPrint + 'a {
        ExternalNodePrettyPrint { node: self, mast_forest }
    }
}

struct ExternalNodePrettyPrint<'a> {
    node: &'a ExternalNode,
    mast_forest: &'a MastForest,
}

impl ExternalNodePrettyPrint<'_> {
    /// Concatenates the provided decorators in a single line. If the list of decorators is not
    /// empty, prepends `prepend` and appends `append` to the decorator document.
    fn concatenate_decorators(
        &self,
        decorator_ids: &DecoratorSpan,
        prepend: Document,
        append: Document,
    ) -> Document {
        let decorators = decorator_ids
            .iter()
            .map(|decorator_id| self.mast_forest[decorator_id].render())
            .reduce(|acc, doc| acc + const_text(" ") + doc)
            .unwrap_or_default();

        if decorators.is_empty() {
            decorators
        } else {
            prepend + decorators + append
        }
    }

    fn single_line_pre_decorators(&self) -> Document {
        self.concatenate_decorators(self.node.before_enter(), Document::Empty, const_text(" "))
    }

    fn single_line_post_decorators(&self) -> Document {
        self.concatenate_decorators(self.node.after_exit(), const_text(" "), Document::Empty)
    }

    fn multi_line_pre_decorators(&self) -> Document {
        self.concatenate_decorators(self.node.before_enter(), Document::Empty, nl())
    }

    fn multi_line_post_decorators(&self) -> Document {
        self.concatenate_decorators(self.node.after_exit(), nl(), Document::Empty)
    }
}

impl crate::prettier::PrettyPrint for ExternalNodePrettyPrint<'_> {
    fn render(&self) -> crate::prettier::Document {
        let external = const_text("external")
            + const_text(".")
            + text(self.node.digest.as_bytes().to_hex_with_prefix());

        let single_line = self.single_line_pre_decorators()
            + external.clone()
            + self.single_line_post_decorators();
        let multi_line =
            self.multi_line_pre_decorators() + external + self.multi_line_post_decorators();

        single_line | multi_line
    }
}

impl fmt::Display for ExternalNodePrettyPrint<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::prettier::PrettyPrint;
        self.pretty_print(f)
    }
}
