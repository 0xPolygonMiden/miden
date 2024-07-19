use alloc::{collections::BTreeMap, vec::Vec};
use vm_core::{
    crypto::hash::RpoDigest,
    mast::{MastForest, MerkleTreeNode},
};

use crate::{
    ast::{FullyQualifiedProcedureName, ProcedureIndex, ProcedureName, ResolvedProcedure},
    LibraryPath, Version,
};

/// A procedure's name, along with its module path.
///
/// The only difference between this type and [`FullyQualifiedProcedureName`] is that
/// [`CompiledFullyQualifiedProcedureName`] doesn't have a [`crate::SourceSpan`].
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

/// Stores the name and digest of a procedure.
#[derive(Debug, Clone)]
pub struct ProcedureInfo {
    pub name: ProcedureName,
    pub digest: RpoDigest,
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
    // TODOP: Add validation that num roots = num exports
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

    pub fn into_compiled_modules(self) -> Vec<CompiledModule> {
        let mut modules_by_path: BTreeMap<LibraryPath, CompiledModule> = BTreeMap::new();

        for (proc_index, proc_name) in self.exports.into_iter().enumerate() {
            modules_by_path
                .entry(proc_name.module_path.clone())
                .and_modify(|compiled_module| {
                    let proc_node_id = self.mast_forest.procedure_roots()[proc_index];
                    let proc_digest = self.mast_forest[proc_node_id].digest();

                    compiled_module.add_procedure(ProcedureInfo {
                        name: proc_name.name.clone(),
                        digest: proc_digest,
                    })
                })
                .or_insert_with(|| {
                    let proc_node_id = self.mast_forest.procedure_roots()[proc_index];
                    let proc_digest = self.mast_forest[proc_node_id].digest();
                    let proc = ProcedureInfo {
                        name: proc_name.name,
                        digest: proc_digest,
                    };

                    CompiledModule::new(proc_name.module_path, core::iter::once(proc))
                });
        }

        modules_by_path.into_values().collect()
    }
}

pub struct CompiledLibraryMetadata {
    pub path: LibraryPath,
    pub version: Version,
}

// TODOP: Rename (?)
#[derive(Debug, Clone)]
pub struct CompiledModule {
    path: LibraryPath,
    procedures: Vec<(ProcedureIndex, ProcedureInfo)>,
}

impl CompiledModule {
    pub fn new(path: LibraryPath, procedures: impl Iterator<Item = ProcedureInfo>) -> Self {
        Self {
            path,
            procedures: procedures
                .enumerate()
                .map(|(idx, proc)| (ProcedureIndex::new(idx), proc))
                .collect(),
        }
    }

    pub fn add_procedure(&mut self, procedure: ProcedureInfo) {
        let index = ProcedureIndex::new(self.procedures.len());
        self.procedures.push((index, procedure));
    }

    pub fn path(&self) -> &LibraryPath {
        &self.path
    }

    // TODOP: Store as `CompiledProcedure`, and add a method `iter()` that iterates with
    // `ProcedureIndex`
    pub fn procedures(&self) -> &[(ProcedureIndex, ProcedureInfo)] {
        &self.procedures
    }

    pub fn resolve(&self, name: &ProcedureName) -> Option<ResolvedProcedure> {
        self.procedures.iter().find_map(|(_, proc)| {
            if &proc.name == name {
                Some(ResolvedProcedure::MastRoot(proc.digest))
            } else {
                None
            }
        })
    }
}
