use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::{
    fmt, mem,
    ops::{Index, IndexMut},
};

use miden_crypto::hash::rpo::RpoDigest;

mod node;
pub use node::{
    BasicBlockNode, CallNode, DynNode, ExternalNode, JoinNode, LoopNode, MastNode, OpBatch,
    OperationOrDecorator, SplitNode, OP_BATCH_SIZE, OP_GROUP_SIZE,
};
use winter_utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

use crate::{AdviceMap, Decorator, DecoratorList, Operation};

mod serialization;

mod merger;
pub(crate) use merger::MastForestMerger;
pub use merger::MastForestRootMap;

mod multi_forest_node_iterator;
pub(crate) use multi_forest_node_iterator::*;

mod node_fingerprint;
pub use node_fingerprint::{DecoratorFingerprint, MastNodeFingerprint};

#[cfg(test)]
mod tests;

// MAST FOREST
// ================================================================================================

/// Represents one or more procedures, represented as a collection of [`MastNode`]s.
///
/// A [`MastForest`] does not have an entrypoint, and hence is not executable. A [`crate::Program`]
/// can be built from a [`MastForest`] to specify an entrypoint.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MastForest {
    /// All of the nodes local to the trees comprising the MAST forest.
    nodes: Vec<MastNode>,

    /// Roots of procedures defined within this MAST forest.
    roots: Vec<MastNodeId>,

    /// All the decorators included in the MAST forest.
    decorators: Vec<Decorator>,

    /// Advice map to be loaded into the VM prior to executing procedures from this MAST forest.
    advice_map: AdviceMap,
}

// ------------------------------------------------------------------------------------------------
/// Constructors
impl MastForest {
    /// Creates a new empty [`MastForest`].
    pub fn new() -> Self {
        Self::default()
    }
}

// ------------------------------------------------------------------------------------------------
/// State mutators
impl MastForest {
    /// The maximum number of nodes that can be stored in a single MAST forest.
    const MAX_NODES: usize = (1 << 30) - 1;

    /// Adds a decorator to the forest, and returns the associated [`DecoratorId`].
    pub fn add_decorator(&mut self, decorator: Decorator) -> Result<DecoratorId, MastForestError> {
        if self.decorators.len() >= u32::MAX as usize {
            return Err(MastForestError::TooManyDecorators);
        }

        let new_decorator_id = DecoratorId(self.decorators.len() as u32);
        self.decorators.push(decorator);

        Ok(new_decorator_id)
    }

    /// Adds a node to the forest, and returns the associated [`MastNodeId`].
    ///
    /// Adding two duplicate nodes will result in two distinct returned [`MastNodeId`]s.
    pub fn add_node(&mut self, node: MastNode) -> Result<MastNodeId, MastForestError> {
        if self.nodes.len() == Self::MAX_NODES {
            return Err(MastForestError::TooManyNodes);
        }

        let new_node_id = MastNodeId(self.nodes.len() as u32);
        self.nodes.push(node);

        Ok(new_node_id)
    }

    /// Adds a basic block node to the forest, and returns the [`MastNodeId`] associated with it.
    pub fn add_block(
        &mut self,
        operations: Vec<Operation>,
        decorators: Option<DecoratorList>,
    ) -> Result<MastNodeId, MastForestError> {
        let block = MastNode::new_basic_block(operations, decorators)?;
        self.add_node(block)
    }

    /// Adds a join node to the forest, and returns the [`MastNodeId`] associated with it.
    pub fn add_join(
        &mut self,
        left_child: MastNodeId,
        right_child: MastNodeId,
    ) -> Result<MastNodeId, MastForestError> {
        let join = MastNode::new_join(left_child, right_child, self)?;
        self.add_node(join)
    }

    /// Adds a split node to the forest, and returns the [`MastNodeId`] associated with it.
    pub fn add_split(
        &mut self,
        if_branch: MastNodeId,
        else_branch: MastNodeId,
    ) -> Result<MastNodeId, MastForestError> {
        let split = MastNode::new_split(if_branch, else_branch, self)?;
        self.add_node(split)
    }

    /// Adds a loop node to the forest, and returns the [`MastNodeId`] associated with it.
    pub fn add_loop(&mut self, body: MastNodeId) -> Result<MastNodeId, MastForestError> {
        let loop_node = MastNode::new_loop(body, self)?;
        self.add_node(loop_node)
    }

    /// Adds a call node to the forest, and returns the [`MastNodeId`] associated with it.
    pub fn add_call(&mut self, callee: MastNodeId) -> Result<MastNodeId, MastForestError> {
        let call = MastNode::new_call(callee, self)?;
        self.add_node(call)
    }

    /// Adds a syscall node to the forest, and returns the [`MastNodeId`] associated with it.
    pub fn add_syscall(&mut self, callee: MastNodeId) -> Result<MastNodeId, MastForestError> {
        let syscall = MastNode::new_syscall(callee, self)?;
        self.add_node(syscall)
    }

    /// Adds a dyn node to the forest, and returns the [`MastNodeId`] associated with it.
    pub fn add_dyn(&mut self) -> Result<MastNodeId, MastForestError> {
        self.add_node(MastNode::new_dyn())
    }

    /// Adds a dyncall node to the forest, and returns the [`MastNodeId`] associated with it.
    pub fn add_dyncall(&mut self) -> Result<MastNodeId, MastForestError> {
        self.add_node(MastNode::new_dyncall())
    }

    /// Adds an external node to the forest, and returns the [`MastNodeId`] associated with it.
    pub fn add_external(&mut self, mast_root: RpoDigest) -> Result<MastNodeId, MastForestError> {
        self.add_node(MastNode::new_external(mast_root))
    }

    /// Marks the given [`MastNodeId`] as being the root of a procedure.
    ///
    /// If the specified node is already marked as a root, this will have no effect.
    ///
    /// # Panics
    /// - if `new_root_id`'s internal index is larger than the number of nodes in this forest (i.e.
    ///   clearly doesn't belong to this MAST forest).
    pub fn make_root(&mut self, new_root_id: MastNodeId) {
        assert!((new_root_id.0 as usize) < self.nodes.len());

        if !self.roots.contains(&new_root_id) {
            self.roots.push(new_root_id);
        }
    }

    /// Removes all nodes in the provided set from the MAST forest. The nodes MUST be orphaned (i.e.
    /// have no parent). Otherwise, this parent's reference is considered "dangling" after the
    /// removal (i.e. will point to an incorrect node after the removal), and this removal operation
    /// would result in an invalid [`MastForest`].
    ///
    /// It also returns the map from old node IDs to new node IDs; or `None` if the set of nodes to
    /// remove was empty. Any [`MastNodeId`] used in reference to the old [`MastForest`] should be
    /// remapped using this map.
    pub fn remove_nodes(
        &mut self,
        nodes_to_remove: &BTreeSet<MastNodeId>,
    ) -> Option<BTreeMap<MastNodeId, MastNodeId>> {
        if nodes_to_remove.is_empty() {
            return None;
        }

        let old_nodes = mem::take(&mut self.nodes);
        let old_root_ids = mem::take(&mut self.roots);
        let (retained_nodes, id_remappings) = remove_nodes(old_nodes, nodes_to_remove);

        self.remap_and_add_nodes(retained_nodes, &id_remappings);
        self.remap_and_add_roots(old_root_ids, &id_remappings);
        Some(id_remappings)
    }

    pub fn set_before_enter(&mut self, node_id: MastNodeId, decorator_ids: DecoratorSpan) {
        self[node_id].set_before_enter(decorator_ids)
    }

    pub fn set_after_exit(&mut self, node_id: MastNodeId, decorator_ids: DecoratorSpan) {
        self[node_id].set_after_exit(decorator_ids)
    }

    /// Merges all `forests` into a new [`MastForest`].
    ///
    /// Merging two forests means combining all their constituent parts, i.e. [`MastNode`]s,
    /// [`Decorator`]s and roots. During this process, any duplicate or
    /// unreachable nodes are removed. Additionally, [`MastNodeId`]s of nodes as well as
    /// [`DecoratorId`]s of decorators may change and references to them are remapped to their new
    /// location.
    ///
    /// For example, consider this representation of a forest's nodes with all of these nodes being
    /// roots:
    ///
    /// ```text
    /// [Block(foo), Block(bar)]
    /// ```
    ///
    /// If we merge another forest into it:
    ///
    /// ```text
    /// [Block(bar), Call(0)]
    /// ```
    ///
    /// then we would expect this forest:
    ///
    /// ```text
    /// [Block(foo), Block(bar), Call(1)]
    /// ```
    ///
    /// - The `Call` to the `bar` block was remapped to its new index (now 1, previously 0).
    /// - The `Block(bar)` was deduplicated any only exists once in the merged forest.
    ///
    /// The function also returns a vector of [`MastForestRootMap`]s, whose length equals the number
    /// of passed `forests`. The indices in the vector correspond to the ones in `forests`. The map
    /// of a given forest contains the new locations of its roots in the merged forest. To
    /// illustrate, the above example would return a vector of two maps:
    ///
    /// ```text
    /// vec![{0 -> 0, 1 -> 1}
    ///      {0 -> 1, 1 -> 2}]
    /// ```
    ///
    /// - The root locations of the original forest are unchanged.
    /// - For the second forest, the `bar` block has moved from index 0 to index 1 in the merged
    ///   forest, and the `Call` has moved from index 1 to 2.
    ///
    /// If any forest being merged contains an `External(qux)` node and another forest contains a
    /// node whose digest is `qux`, then the external node will be replaced with the `qux` node,
    /// which is effectively deduplication. Decorators are ignored when it comes to merging
    /// External nodes. This means that an External node with decorators may be replaced by a node
    /// without decorators or vice versa.
    pub fn merge<'forest>(
        forests: impl IntoIterator<Item = &'forest MastForest>,
    ) -> Result<(MastForest, MastForestRootMap), MastForestError> {
        MastForestMerger::merge(forests)
    }

    /// Adds a basic block node to the forest, and returns the [`MastNodeId`] associated with it.
    ///
    /// It is assumed that the decorators have not already been added to the MAST forest. If they
    /// were, they will be added again (and result in a different set of [`DecoratorId`]s).
    #[cfg(test)]
    pub fn add_block_with_raw_decorators(
        &mut self,
        operations: Vec<Operation>,
        decorators: Vec<(usize, Decorator)>,
    ) -> Result<MastNodeId, MastForestError> {
        let block = MastNode::new_basic_block_with_raw_decorators(operations, decorators, self)?;
        self.add_node(block)
    }
}

/// Helpers
impl MastForest {
    /// Adds all provided nodes to the internal set of nodes, remapping all [`MastNodeId`]
    /// references in those nodes.
    ///
    /// # Panics
    /// - Panics if the internal set of nodes is not empty.
    fn remap_and_add_nodes(
        &mut self,
        nodes_to_add: Vec<MastNode>,
        id_remappings: &BTreeMap<MastNodeId, MastNodeId>,
    ) {
        assert!(self.nodes.is_empty());

        // Add each node to the new MAST forest, making sure to rewrite any outdated internal
        // `MastNodeId`s
        for live_node in nodes_to_add {
            match &live_node {
                MastNode::Join(join_node) => {
                    let first_child =
                        id_remappings.get(&join_node.first()).copied().unwrap_or(join_node.first());
                    let second_child = id_remappings
                        .get(&join_node.second())
                        .copied()
                        .unwrap_or(join_node.second());

                    self.add_join(first_child, second_child).unwrap();
                },
                MastNode::Split(split_node) => {
                    let on_true_child = id_remappings
                        .get(&split_node.on_true())
                        .copied()
                        .unwrap_or(split_node.on_true());
                    let on_false_child = id_remappings
                        .get(&split_node.on_false())
                        .copied()
                        .unwrap_or(split_node.on_false());

                    self.add_split(on_true_child, on_false_child).unwrap();
                },
                MastNode::Loop(loop_node) => {
                    let body_id =
                        id_remappings.get(&loop_node.body()).copied().unwrap_or(loop_node.body());

                    self.add_loop(body_id).unwrap();
                },
                MastNode::Call(call_node) => {
                    let callee_id = id_remappings
                        .get(&call_node.callee())
                        .copied()
                        .unwrap_or(call_node.callee());

                    if call_node.is_syscall() {
                        self.add_syscall(callee_id).unwrap();
                    } else {
                        self.add_call(callee_id).unwrap();
                    }
                },
                MastNode::Block(_) | MastNode::Dyn(_) | MastNode::External(_) => {
                    self.add_node(live_node).unwrap();
                },
            }
        }
    }

    /// Remaps and adds all old root ids to the internal set of roots.
    ///
    /// # Panics
    /// - Panics if the internal set of roots is not empty.
    fn remap_and_add_roots(
        &mut self,
        old_root_ids: Vec<MastNodeId>,
        id_remappings: &BTreeMap<MastNodeId, MastNodeId>,
    ) {
        assert!(self.roots.is_empty());

        for old_root_id in old_root_ids {
            let new_root_id = id_remappings.get(&old_root_id).copied().unwrap_or(old_root_id);
            self.make_root(new_root_id);
        }
    }
}

/// Returns the set of nodes that are live, as well as the mapping from "old ID" to "new ID" for all
/// live nodes.
fn remove_nodes(
    mast_nodes: Vec<MastNode>,
    nodes_to_remove: &BTreeSet<MastNodeId>,
) -> (Vec<MastNode>, BTreeMap<MastNodeId, MastNodeId>) {
    // Note: this allows us to safely use `usize as u32`, guaranteeing that it won't wrap around.
    assert!(mast_nodes.len() < u32::MAX as usize);

    let mut retained_nodes = Vec::with_capacity(mast_nodes.len());
    let mut id_remappings = BTreeMap::new();

    for (old_node_index, old_node) in mast_nodes.into_iter().enumerate() {
        let old_node_id: MastNodeId = MastNodeId(old_node_index as u32);

        if !nodes_to_remove.contains(&old_node_id) {
            let new_node_id: MastNodeId = MastNodeId(retained_nodes.len() as u32);
            id_remappings.insert(old_node_id, new_node_id);

            retained_nodes.push(old_node);
        }
    }

    (retained_nodes, id_remappings)
}

// ------------------------------------------------------------------------------------------------

/// Public accessors
impl MastForest {
    /// Returns the [`Decorator`] associated with the provided [`DecoratorId`] if valid, or else
    /// `None`.
    ///
    /// This is the fallible version of indexing (e.g. `mast_forest[decorator_id]`).
    #[inline(always)]
    pub fn get_decorator_by_id(&self, decorator_id: DecoratorId) -> Option<&Decorator> {
        let idx = decorator_id.0 as usize;

        self.decorators.get(idx)
    }

    /// Returns the [`MastNode`] associated with the provided [`MastNodeId`] if valid, or else
    /// `None`.
    ///
    /// This is the fallible version of indexing (e.g. `mast_forest[node_id]`).
    #[inline(always)]
    pub fn get_node_by_id(&self, node_id: MastNodeId) -> Option<&MastNode> {
        let idx = node_id.0 as usize;

        self.nodes.get(idx)
    }

    /// Returns the [`MastNodeId`] of the procedure associated with a given digest, if any.
    #[inline(always)]
    pub fn find_procedure_root(&self, digest: RpoDigest) -> Option<MastNodeId> {
        self.roots.iter().find(|&&root_id| self[root_id].digest() == digest).copied()
    }

    /// Returns true if a node with the specified ID is a root of a procedure in this MAST forest.
    pub fn is_procedure_root(&self, node_id: MastNodeId) -> bool {
        self.roots.contains(&node_id)
    }

    /// Returns an iterator over the digests of all procedures in this MAST forest.
    pub fn procedure_digests(&self) -> impl Iterator<Item = RpoDigest> + '_ {
        self.roots.iter().map(|&root_id| self[root_id].digest())
    }

    /// Returns an iterator over the digests of local procedures in this MAST forest.
    ///
    /// A local procedure is defined as a procedure which is not a single external node.
    pub fn local_procedure_digests(&self) -> impl Iterator<Item = RpoDigest> + '_ {
        self.roots.iter().filter_map(|&root_id| {
            let node = &self[root_id];
            if node.is_external() {
                None
            } else {
                Some(node.digest())
            }
        })
    }

    /// Returns an iterator over the IDs of the procedures in this MAST forest.
    pub fn procedure_roots(&self) -> &[MastNodeId] {
        &self.roots
    }

    /// Returns the number of procedures in this MAST forest.
    pub fn num_procedures(&self) -> u32 {
        self.roots
            .len()
            .try_into()
            .expect("MAST forest contains more than 2^32 procedures.")
    }

    /// Returns the number of nodes in this MAST forest.
    pub fn num_nodes(&self) -> u32 {
        self.nodes.len() as u32
    }

    /// Returns the underlying nodes in this MAST forest.
    pub fn nodes(&self) -> &[MastNode] {
        &self.nodes
    }

    pub fn decorators(&self) -> &[Decorator] {
        &self.decorators
    }

    pub fn advice_map(&self) -> &AdviceMap {
        &self.advice_map
    }

    pub fn advice_map_mut(&mut self) -> &mut AdviceMap {
        &mut self.advice_map
    }
}

impl Index<MastNodeId> for MastForest {
    type Output = MastNode;

    #[inline(always)]
    fn index(&self, node_id: MastNodeId) -> &Self::Output {
        let idx = node_id.0 as usize;

        &self.nodes[idx]
    }
}

impl IndexMut<MastNodeId> for MastForest {
    #[inline(always)]
    fn index_mut(&mut self, node_id: MastNodeId) -> &mut Self::Output {
        let idx = node_id.0 as usize;

        &mut self.nodes[idx]
    }
}

impl Index<DecoratorId> for MastForest {
    type Output = Decorator;

    #[inline(always)]
    fn index(&self, decorator_id: DecoratorId) -> &Self::Output {
        let idx = decorator_id.0 as usize;

        &self.decorators[idx]
    }
}

impl IndexMut<DecoratorId> for MastForest {
    #[inline(always)]
    fn index_mut(&mut self, decorator_id: DecoratorId) -> &mut Self::Output {
        let idx = decorator_id.0 as usize;
        &mut self.decorators[idx]
    }
}

// MAST NODE ID
// ================================================================================================

/// An opaque handle to a [`MastNode`] in some [`MastForest`]. It is the responsibility of the user
/// to use a given [`MastNodeId`] with the corresponding [`MastForest`].
///
/// Note that the [`MastForest`] does *not* ensure that equal [`MastNode`]s have equal
/// [`MastNodeId`] handles. Hence, [`MastNodeId`] equality must not be used to test for equality of
/// the underlying [`MastNode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MastNodeId(u32);

impl MastNodeId {
    /// Returns a new `MastNodeId` with the provided inner value, or an error if the provided
    /// `value` is greater than the number of nodes in the forest.
    ///
    /// For use in deserialization.
    pub fn from_u32_safe(
        value: u32,
        mast_forest: &MastForest,
    ) -> Result<Self, DeserializationError> {
        Self::from_u32_with_node_count(value, mast_forest.nodes.len())
    }

    /// Returns a new [`MastNodeId`] with the provided `node_id`, or an error if `node_id` is
    /// greater than the number of nodes in the [`MastForest`] for which this ID is being
    /// constructed.
    pub fn from_usize_safe(
        node_id: usize,
        mast_forest: &MastForest,
    ) -> Result<Self, DeserializationError> {
        let node_id: u32 = node_id.try_into().map_err(|_| {
            DeserializationError::InvalidValue(format!(
                "node id '{node_id}' does not fit into a u32"
            ))
        })?;
        MastNodeId::from_u32_safe(node_id, mast_forest)
    }

    /// Returns a new [`MastNodeId`] from the given `value` without checking its validity.
    pub(crate) fn new_unchecked(value: u32) -> Self {
        Self(value)
    }

    /// Returns a new [`MastNodeId`] with the provided `id`, or an error if `id` is greater or equal
    /// to `node_count`. The `node_count` is the total number of nodes in the [`MastForest`] for
    /// which this ID is being constructed.
    ///
    /// This function can be used when deserializing an id whose corresponding node is not yet in
    /// the forest and [`Self::from_u32_safe`] would fail. For instance, when deserializing the ids
    /// referenced by the Join node in this forest:
    ///
    /// ```text
    /// [Join(1, 2), Block(foo), Block(bar)]
    /// ```
    ///
    /// Since it is less safe than [`Self::from_u32_safe`] and usually not needed it is not public.
    pub(super) fn from_u32_with_node_count(
        id: u32,
        node_count: usize,
    ) -> Result<Self, DeserializationError> {
        if (id as usize) < node_count {
            Ok(Self(id))
        } else {
            Err(DeserializationError::InvalidValue(format!(
                "Invalid deserialized MAST node ID '{}', but {} is the number of nodes in the forest",
                id, node_count,
            )))
        }
    }

    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl From<MastNodeId> for usize {
    fn from(value: MastNodeId) -> Self {
        value.0 as usize
    }
}

impl From<MastNodeId> for u32 {
    fn from(value: MastNodeId) -> Self {
        value.0
    }
}

impl From<&MastNodeId> for u32 {
    fn from(value: &MastNodeId) -> Self {
        value.0
    }
}

impl fmt::Display for MastNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MastNodeId({})", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Copy)]
pub struct DecoratorSpan {
    /// Offset into the decorators vector of the mast forest.
    offset: u32,

    /// The number of decorators in this span.
    num_decorators: u32,
}

impl DecoratorSpan {
    pub fn new_collection(decorator_ids: Vec<DecoratorId>) -> Vec<DecoratorSpan> {
        // Test that this returns an empty decoratorspan if the DecoratorId list is empty
        let mut sorted_ids = decorator_ids;
        sorted_ids.sort_unstable();

        sorted_ids
            .into_iter()
            .fold(Vec::new(), |mut spans: Vec<DecoratorSpan>, id| {
                if let Some(last) = spans.last_mut() {
                    if last.offset + last.num_decorators == id.as_u32() {
                        last.num_decorators += 1;
                        return spans;
                    }
                }
                spans.push(DecoratorSpan {
                    offset: id.as_u32(),
                    num_decorators: 1,
                });
                spans
            })
    }

    pub fn from_raw_ops_decorators(decorators: Vec<(usize, DecoratorId)>) -> Option<DecoratorList> {
        if !decorators.is_empty() {
            let mut decorators_list: DecoratorList = Vec::new();
            let mut current_index: Option<usize> = None;
            let mut current_group: Vec<DecoratorId> = Vec::new();

            for (index, decorator_id) in decorators{
                if Some(index) != current_index {
                    //process the previous group
                    if !current_group.is_empty() {
                        let spans = DecoratorSpan::new_collection(current_group);
                        if let Some(span) = spans.into_iter().next() {
                            decorators_list.push((index, span));
                        }
                    }
                    // Start a new group
                    current_index = Some(index);
                    current_group = Vec::new();
                }
                current_group.push(decorator_id);
            }

            // Process the last group
            if let Some(idx) = current_index {
                if !current_group.is_empty() {
                    let spans = DecoratorSpan::new_collection(current_group);
                    if let Some(span) = spans.into_iter().next() {
                        decorators_list.push((idx, span));
                    }
                }
            }
            Some(decorators_list)
        } else {
            None
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = DecoratorId> { //Should this return a reference?
        (self.offset..self.offset + self.num_decorators).map(DecoratorId)
    }

    pub fn is_empty(&self) -> bool {
        self.num_decorators == 0
    }

    pub fn read_safe<R: ByteReader>(
        source: &mut R,
        mast_forest: &MastForest,
    ) -> Result<Self, DeserializationError> {
        let value = Self::read_from(source)?;
        let last_decorator_id = (value.offset + value.num_decorators) as usize;
        if last_decorator_id < mast_forest.decorators.len() {
            Ok(Self { offset: value.offset, num_decorators: value.num_decorators })
        } else {
            Err(DeserializationError::InvalidValue(format!(
                "Invalid deserialized MAST decorator span with offset'{}' and num_decorators'{}', but only {} decorators in the forest",
                value.offset, value.num_decorators,
                mast_forest.nodes.len(),
            )))
        }
    }
}

impl Deserializable for DecoratorSpan {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let offset = source.read_u32()?;
        let num_decorators = source.read_u32()?;
        Ok(DecoratorSpan { offset, num_decorators })
    }
}
impl From<Vec<DecoratorId>> for DecoratorSpan {
    fn from(decorator_ids: Vec<DecoratorId>) -> Self {
        // Create a DecoratorSpan based on the size of the list and the first offset
        let num_decorators = decorator_ids.len() as u32;
        let offset = if num_decorators > 0 {
            decorator_ids[0].into()
        } else {
            0
        };

        DecoratorSpan {
            offset,
            num_decorators,
        }
    }
}

impl Serializable for DecoratorSpan {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.offset.write_into(target);
        self.num_decorators.write_into(target);
    }
}

// DECORATOR ID
// ================================================================================================

/// An opaque handle to a [`Decorator`] in some [`MastForest`]. It is the responsibility of the user
/// to use a given [`DecoratorId`] with the corresponding [`MastForest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DecoratorId(u32);

impl DecoratorId {
    /// Returns a new `DecoratorId` with the provided inner value, or an error if the provided
    /// `value` is greater than the number of nodes in the forest.
    ///
    /// For use in deserialization.
    pub fn from_u32_safe(
        value: u32,
        mast_forest: &MastForest,
    ) -> Result<Self, DeserializationError> {
        if (value as usize) < mast_forest.decorators.len() {
            Ok(Self(value))
        } else {
            Err(DeserializationError::InvalidValue(format!(
                "Invalid deserialized MAST decorator id '{}', but only {} decorators in the forest",
                value,
                mast_forest.nodes.len(),
            )))
        }
    }

    /// Creates a new [`DecoratorId`] without checking its validity.
    pub(crate) fn new_unchecked(value: u32) -> Self {
        Self(value)
    }

    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl From<DecoratorId> for usize {
    fn from(value: DecoratorId) -> Self {
        value.0 as usize
    }
}

impl From<DecoratorId> for u32 {
    fn from(value: DecoratorId) -> Self {
        value.0
    }
}

impl From<&DecoratorId> for u32 {
    fn from(value: &DecoratorId) -> Self {
        value.0
    }
}

impl fmt::Display for DecoratorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DecoratorId({})", self.0)
    }
}

impl Serializable for DecoratorId {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target)
    }
}

// MAST FOREST ERROR
// ================================================================================================

/// Represents the types of errors that can occur when dealing with MAST forest.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum MastForestError {
    #[error("MAST forest decorator count exceeds the maximum of {} decorators", u32::MAX)]
    TooManyDecorators,
    #[error("MAST forest node count exceeds the maximum of {} nodes", MastForest::MAX_NODES)]
    TooManyNodes,
    #[error("node id {0} is greater than or equal to forest length {1}")]
    NodeIdOverflow(MastNodeId, usize),
    #[error("decorator id {0} is greater than or equal to decorator count {1}")]
    DecoratorIdOverflow(DecoratorId, usize),
    #[error("decorator span with offset '{0}' and num_decorators '{1}' should remap when merging, but was not")]
    DecoratorSpanMissing(u32, u32),
    #[error("basic block cannot be created from an empty list of operations")]
    EmptyBasicBlock,
    #[error("decorator root of child with node id {0} is missing but is required for fingerprint computation")]
    ChildFingerprintMissing(MastNodeId),
    #[error("advice map key {0} already exists when merging forests")]
    AdviceMapKeyCollisionOnMerge(RpoDigest),
}
