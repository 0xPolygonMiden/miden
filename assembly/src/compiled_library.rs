use alloc::{string::String, vec::Vec};
use vm_core::{crypto::hash::RpoDigest, mast::MastForest};

use crate::{
    ast::{FullyQualifiedProcedureName, ProcedureName},
    LibraryPath, Version,
};

// TODOP: Refactor `FullyQualifiedProcedureName` instead, and use `Span<FQDN>` where needed?
pub struct CompiledFullyQualifiedProcedureName {
    /// The module path for this procedure.
    pub module_path: LibraryPath,
    /// The name of the procedure.
    pub name: ProcedureName,
}

impl CompiledFullyQualifiedProcedureName {
    pub fn new(module_path: LibraryPath, name: ProcedureName) -> Self {
        Self { module_path, name }
    }
}

impl From<FullyQualifiedProcedureName> for CompiledFullyQualifiedProcedureName {
    fn from(fqdn: FullyQualifiedProcedureName) -> Self {
        Self {
            module_path: fqdn.module,
            name: fqdn.name,
        }
    }
}

#[derive(Clone)]
pub struct CompiledProcedure {
    pub name: ProcedureName,
    pub digest: RpoDigest,
}

// TODOP: Remove methods in favor of pub fields?
impl CompiledProcedure {
    pub fn name(&self) -> &ProcedureName {
        &self.name
    }

    pub fn digest(&self) -> &RpoDigest {
        &self.digest
    }
}

// TODOP: Move into `miden-core` along with `LibraryPath`
pub struct CompiledLibrary {
    mast_forest: MastForest,
    // a path for every `root` in the associated [MastForest]
    exports: Vec<CompiledFullyQualifiedProcedureName>,
    metadata: CompiledLibraryMetadata,
}

/// Constructors
impl CompiledLibrary {
    pub fn new(
        mast_forest: MastForest,
        exports: Vec<CompiledFullyQualifiedProcedureName>,
        metadata: CompiledLibraryMetadata,
    ) -> Self {
        Self {
            mast_forest,
            exports,
            metadata,
        }
    }
}

impl CompiledLibrary {
    pub fn mast_forest(&self) -> &MastForest {
        &self.mast_forest
    }

    pub fn exports(&self) -> &[CompiledFullyQualifiedProcedureName] {
        &self.exports
    }

    pub fn metadata(&self) -> &CompiledLibraryMetadata {
        &self.metadata
    }
}

pub struct CompiledLibraryMetadata {
    pub name: String,
    pub version: Version,
}
