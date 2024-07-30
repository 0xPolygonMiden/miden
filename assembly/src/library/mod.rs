use alloc::{collections::BTreeMap, vec::Vec};

use vm_core::crypto::hash::RpoDigest;
use vm_core::mast::MastForest;
use vm_core::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};
use vm_core::Kernel;

use crate::ast::{
    self, AstSerdeOptions, FullyQualifiedProcedureName, ProcedureIndex, ProcedureName,
};

mod error;
mod masl;
mod namespace;
mod path;
mod version;

pub use self::error::{CompiledLibraryError, LibraryError};
pub use self::masl::MaslLibrary;
pub use self::namespace::{LibraryNamespace, LibraryNamespaceError};
pub use self::path::{LibraryPath, LibraryPathComponent, PathError};
pub use self::version::{Version, VersionError};

#[cfg(test)]
mod tests;

// COMPILED LIBRARY
// ================================================================================================

/// Represents a library where all modules modules were compiled into a [`MastForest`].
pub struct CompiledLibrary {
    mast_forest: MastForest,
    // a path for every `root` in the associated MAST forest
    exports: Vec<FullyQualifiedProcedureName>,
}

/// Constructors
impl CompiledLibrary {
    /// Constructs a new [`CompiledLibrary`].
    pub fn new(
        mast_forest: MastForest,
        exports: Vec<FullyQualifiedProcedureName>,
    ) -> Result<Self, CompiledLibraryError> {
        if mast_forest.num_procedures() as usize != exports.len() {
            return Err(CompiledLibraryError::InvalidExports {
                exports_len: exports.len(),
                roots_len: mast_forest.num_procedures() as usize,
            });
        }

        Ok(Self {
            mast_forest,
            exports,
        })
    }
}

/// Accessors
impl CompiledLibrary {
    /// Returns the inner [`MastForest`].
    pub fn mast_forest(&self) -> &MastForest {
        &self.mast_forest
    }

    /// Returns the fully qualified name of all procedures exported by the library.
    pub fn exports(&self) -> &[FullyQualifiedProcedureName] {
        &self.exports
    }
}

/// Conversions
impl CompiledLibrary {
    /// Returns an iterator over the module infos of the library.
    pub fn into_module_infos(self) -> impl Iterator<Item = ModuleInfo> {
        let mut modules_by_path: BTreeMap<LibraryPath, ModuleInfo> = BTreeMap::new();

        for (proc_index, proc_name) in self.exports.into_iter().enumerate() {
            modules_by_path
                .entry(proc_name.module.clone())
                .and_modify(|compiled_module| {
                    let proc_node_id = self.mast_forest.procedure_roots()[proc_index];
                    let proc_digest = self.mast_forest[proc_node_id].digest();

                    compiled_module.add_procedure_info(ProcedureInfo {
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

                    ModuleInfo::new(proc_name.module, vec![proc])
                });
        }

        modules_by_path.into_values()
    }
}

/// Serialization
impl CompiledLibrary {
    /// Serialize to `target` using `options`
    pub fn write_into_with_options<W: ByteWriter>(&self, target: &mut W, options: AstSerdeOptions) {
        let Self {
            mast_forest,
            exports,
        } = self;

        mast_forest.write_into(target);

        target.write_usize(exports.len());
        for proc_name in exports {
            proc_name.write_into_with_options(target, options);
        }
    }

    /// Deserialize from `source` using `options`
    pub fn read_from_with_options<R: ByteReader>(
        source: &mut R,
        options: AstSerdeOptions,
    ) -> Result<Self, DeserializationError> {
        let mast_forest = MastForest::read_from(source)?;

        let num_exports = source.read_usize()?;
        let mut exports = Vec::with_capacity(num_exports);
        for _ in 0..num_exports {
            let proc_name = FullyQualifiedProcedureName::read_from_with_options(source, options)?;
            exports.push(proc_name);
        }

        Ok(Self {
            mast_forest,
            exports,
        })
    }
}

// KERNEL LIBRARY
// ================================================================================================

/// Represents a library containing a Miden VM kernel.
///
/// This differs from the regular [CompiledLibrary] as follows:
/// - All exported procedures must be exported directly from the kernel namespace (i.e., `#sys`).
/// - The number of exported procedures cannot exceed [Kernel::MAX_NUM_PROCEDURES] (i.e., 256).
pub struct KernelLibrary {
    kernel: Kernel,
    kernel_info: ModuleInfo,
    library: CompiledLibrary,
}

impl KernelLibrary {
    /// Destructures this kernel library into individual parts.
    pub fn into_parts(self) -> (Kernel, ModuleInfo, MastForest) {
        (self.kernel, self.kernel_info, self.library.mast_forest)
    }
}

impl TryFrom<CompiledLibrary> for KernelLibrary {
    type Error = CompiledLibraryError;

    fn try_from(library: CompiledLibrary) -> Result<Self, Self::Error> {
        let kernel_path = LibraryPath::from(LibraryNamespace::Kernel);
        let mut kernel_procs = Vec::with_capacity(library.exports.len());
        let mut proc_digests = Vec::with_capacity(library.exports.len());

        for (proc_index, proc_path) in library.exports.iter().enumerate() {
            // make sure all procedures are exported directly from the #sys module
            if proc_path.module != kernel_path {
                return Err(CompiledLibraryError::InvalidKernelExport {
                    procedure_path: proc_path.clone(),
                });
            }

            let proc_node_id = library.mast_forest.procedure_roots()[proc_index];
            let proc_digest = library.mast_forest[proc_node_id].digest();

            proc_digests.push(proc_digest);
            kernel_procs.push(ProcedureInfo {
                name: proc_path.name.clone(),
                digest: proc_digest,
            });
        }

        let kernel = Kernel::new(&proc_digests)?;
        let module_info = ModuleInfo::new(kernel_path, kernel_procs);

        Ok(Self {
            kernel,
            kernel_info: module_info,
            library,
        })
    }
}

/// Serialization
impl KernelLibrary {
    /// Serialize to `target` using `options`
    pub fn write_into_with_options<W: ByteWriter>(&self, target: &mut W, options: AstSerdeOptions) {
        let Self {
            kernel: _,
            kernel_info: _,
            library,
        } = self;

        library.write_into_with_options(target, options);
    }

    /// Deserialize from `source` using `options`
    pub fn read_from_with_options<R: ByteReader>(
        source: &mut R,
        options: AstSerdeOptions,
    ) -> Result<Self, DeserializationError> {
        let library = CompiledLibrary::read_from_with_options(source, options)?;

        Self::try_from(library).map_err(|err| {
            DeserializationError::InvalidValue(format!(
                "Failed to deserialize kernel library: {err}"
            ))
        })
    }
}

// MODULE INFO
// ================================================================================================

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    path: LibraryPath,
    procedure_infos: Vec<ProcedureInfo>,
}

impl ModuleInfo {
    /// Returns a new [`ModuleInfo`] instantiated from the provided procedures.
    ///
    /// Note: this constructor assumes that the fully-qualified names of the provided procedures
    /// are consistent with the provided module path, but this is not checked.
    fn new(path: LibraryPath, procedures: Vec<ProcedureInfo>) -> Self {
        Self {
            path,
            procedure_infos: procedures,
        }
    }

    /// Adds a [`ProcedureInfo`] to the module.
    pub fn add_procedure_info(&mut self, procedure: ProcedureInfo) {
        self.procedure_infos.push(procedure);
    }

    /// Returns the module's library path.
    pub fn path(&self) -> &LibraryPath {
        &self.path
    }

    /// Returns the number of procedures in the module.
    pub fn num_procedures(&self) -> usize {
        self.procedure_infos.len()
    }

    /// Returns an iterator over the procedure infos in the module with their corresponding
    /// procedure index in the module.
    pub fn procedure_infos(&self) -> impl Iterator<Item = (ProcedureIndex, &ProcedureInfo)> {
        self.procedure_infos
            .iter()
            .enumerate()
            .map(|(idx, proc)| (ProcedureIndex::new(idx), proc))
    }

    /// Returns an iterator over the MAST roots of procedures defined in this module.
    pub fn procedure_digests(&self) -> impl Iterator<Item = RpoDigest> + '_ {
        self.procedure_infos.iter().map(|p| p.digest)
    }

    /// Returns the [`ProcedureInfo`] of the procedure at the provided index, if any.
    pub fn get_proc_info_by_index(&self, index: ProcedureIndex) -> Option<&ProcedureInfo> {
        self.procedure_infos.get(index.as_usize())
    }

    /// Returns the digest of the procedure with the provided name, if any.
    pub fn get_proc_digest_by_name(&self, name: &ProcedureName) -> Option<RpoDigest> {
        self.procedure_infos.iter().find_map(|proc_info| {
            if &proc_info.name == name {
                Some(proc_info.digest)
            } else {
                None
            }
        })
    }
}

/// Stores the name and digest of a procedure.
#[derive(Debug, Clone)]
pub struct ProcedureInfo {
    pub name: ProcedureName,
    pub digest: RpoDigest,
}

// LIBRARY
// ===============================================================================================

/// Maximum number of modules in a library.
const MAX_MODULES: usize = u16::MAX as usize;

/// Maximum number of dependencies in a library.
const MAX_DEPENDENCIES: usize = u16::MAX as usize;

/// A library definition that provides AST modules for the compilation process.
pub trait Library {
    /// Returns the root namespace of this library.
    fn root_ns(&self) -> &LibraryNamespace;

    /// Returns the version number of this library.
    fn version(&self) -> &Version;

    /// Iterate the modules available in the library.
    fn modules(&self) -> impl ExactSizeIterator<Item = &ast::Module> + '_;

    /// Returns the dependency libraries of this library.
    fn dependencies(&self) -> &[LibraryNamespace];

    /// Returns the module stored at the provided path.
    fn get_module(&self, path: &LibraryPath) -> Option<&ast::Module> {
        self.modules().find(|&module| module.path() == path)
    }
}

impl<T> Library for &T
where
    T: Library,
{
    fn root_ns(&self) -> &LibraryNamespace {
        T::root_ns(self)
    }

    fn version(&self) -> &Version {
        T::version(self)
    }

    fn modules(&self) -> impl ExactSizeIterator<Item = &ast::Module> + '_ {
        T::modules(self)
    }

    fn dependencies(&self) -> &[LibraryNamespace] {
        T::dependencies(self)
    }

    fn get_module(&self, path: &LibraryPath) -> Option<&ast::Module> {
        T::get_module(self, path)
    }
}
