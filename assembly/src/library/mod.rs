use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    sync::Arc,
    vec::Vec,
};

use vm_core::{
    crypto::hash::RpoDigest,
    debuginfo::Span,
    mast::{MastForest, MastNodeId},
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
    Kernel,
};

use crate::ast::{Ident, ProcedureName, QualifiedProcedureName};

mod error;
mod module;
mod namespace;
mod path;
mod version;

pub use module::{ModuleInfo, ProcedureInfo};

pub use self::{
    error::LibraryError,
    namespace::{LibraryNamespace, LibraryNamespaceError},
    path::{LibraryPath, LibraryPathComponent, PathError},
    version::{Version, VersionError},
};

#[cfg(test)]
mod tests;

// LIBRARY
// ================================================================================================

/// Represents a library where all modules were compiled into a [`MastForest`].
///
/// A library exports a set of one or more procedures. Currently, all exported procedures belong
/// to the same top-level namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Library {
    /// The content hash of this library, formed by hashing the roots of all exports in
    /// lexicographical order (by digest, not procedure name)
    digest: RpoDigest,
    /// A map between procedure paths and the corresponding procedure roots in the MAST forest.
    /// Multiple paths can map to the same root, and also, some roots may not be associated with
    /// any paths.
    ///
    /// Note that we use `MastNodeId` as an identifier for procedures instead of MAST root, since 2
    /// different procedures with the same MAST root can be different due to the decorators they
    /// contain. However, note that `MastNodeId` is also not a unique identifier for procedures; if
    /// the procedures have the same MAST root and decorators, they will have the same
    /// `MastNodeId`.
    exports: BTreeMap<QualifiedProcedureName, MastNodeId>,
    /// The MAST forest underlying this library.
    mast_forest: Arc<MastForest>,
}

impl AsRef<Library> for Library {
    #[inline(always)]
    fn as_ref(&self) -> &Library {
        self
    }
}

// ------------------------------------------------------------------------------------------------
/// Constructors
impl Library {
    /// Constructs a new [`Library`] from the provided MAST forest and a set of exports.
    ///
    /// # Errors
    /// Returns an error if the set of exports is empty.
    /// Returns an error if any of the specified exports do not have a corresponding procedure root
    /// in the provided MAST forest.
    pub fn new(
        mast_forest: Arc<MastForest>,
        exports: BTreeMap<QualifiedProcedureName, MastNodeId>,
    ) -> Result<Self, LibraryError> {
        if exports.is_empty() {
            return Err(LibraryError::NoExport);
        }
        for (fqn, &proc_body_id) in exports.iter() {
            if !mast_forest.is_procedure_root(proc_body_id) {
                return Err(LibraryError::NoProcedureRootForExport { procedure_path: fqn.clone() });
            }
        }

        let digest = compute_content_hash(&exports, &mast_forest);

        Ok(Self { digest, exports, mast_forest })
    }
}

// ------------------------------------------------------------------------------------------------
/// Public accessors
impl Library {
    /// Returns the [RpoDigest] representing the content hash of this library
    pub fn digest(&self) -> &RpoDigest {
        &self.digest
    }

    /// Returns the fully qualified name of all procedures exported by the library.
    pub fn exports(&self) -> impl Iterator<Item = &QualifiedProcedureName> {
        self.exports.keys()
    }

    /// Returns the number of exports in this library.
    pub fn num_exports(&self) -> usize {
        self.exports.len()
    }

    /// Returns a MAST node ID associated with the specified exported procedure.
    ///
    /// # Panics
    /// Panics if the specified procedure is not exported from this library.
    pub fn get_export_node_id(&self, proc_name: &QualifiedProcedureName) -> MastNodeId {
        *self.exports.get(proc_name).expect("procedure not exported from the library")
    }

    /// Returns true if the specified exported procedure is re-exported from a dependency.
    pub fn is_reexport(&self, proc_name: &QualifiedProcedureName) -> bool {
        self.exports
            .get(proc_name)
            .map(|&node_id| self.mast_forest[node_id].is_external())
            .unwrap_or(false)
    }

    /// Returns a reference to the inner [`MastForest`].
    pub fn mast_forest(&self) -> &Arc<MastForest> {
        &self.mast_forest
    }
}

/// Conversions
impl Library {
    /// Returns an iterator over the module infos of the library.
    pub fn module_infos(&self) -> impl Iterator<Item = ModuleInfo> {
        let mut modules_by_path: BTreeMap<LibraryPath, ModuleInfo> = BTreeMap::new();

        for (proc_name, &proc_root_node_id) in self.exports.iter() {
            modules_by_path
                .entry(proc_name.module.clone())
                .and_modify(|compiled_module| {
                    let proc_digest = self.mast_forest[proc_root_node_id].digest();
                    compiled_module.add_procedure(proc_name.name.clone(), proc_digest);
                })
                .or_insert_with(|| {
                    let mut module_info = ModuleInfo::new(proc_name.module.clone());

                    let proc_digest = self.mast_forest[proc_root_node_id].digest();
                    module_info.add_procedure(proc_name.name.clone(), proc_digest);

                    module_info
                });
        }

        modules_by_path.into_values()
    }
}

impl Serializable for Library {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { digest: _, exports, mast_forest } = self;

        mast_forest.write_into(target);

        target.write_usize(exports.len());
        for (proc_name, proc_node_id) in exports {
            proc_name.module.write_into(target);
            proc_name.name.as_str().write_into(target);
            target.write_u32(proc_node_id.as_u32());
        }
    }
}

impl Deserializable for Library {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mast_forest = Arc::new(MastForest::read_from(source)?);

        let num_exports = source.read_usize()?;
        if num_exports == 0 {
            return Err(DeserializationError::InvalidValue(String::from("No exported procedures")));
        };
        let mut exports = BTreeMap::new();
        for _ in 0..num_exports {
            let proc_module = source.read()?;
            let proc_name: String = source.read()?;
            let proc_name = ProcedureName::new_unchecked(Ident::new_unchecked(Span::unknown(
                Arc::from(proc_name),
            )));
            let proc_name = QualifiedProcedureName::new(proc_module, proc_name);
            let proc_node_id = MastNodeId::from_u32_safe(source.read_u32()?, &mast_forest)?;

            exports.insert(proc_name, proc_node_id);
        }

        let digest = compute_content_hash(&exports, &mast_forest);

        Ok(Self { digest, exports, mast_forest })
    }
}

fn compute_content_hash(
    exports: &BTreeMap<QualifiedProcedureName, MastNodeId>,
    mast_forest: &MastForest,
) -> RpoDigest {
    let digests = BTreeSet::from_iter(exports.values().map(|&id| mast_forest[id].digest()));
    digests
        .into_iter()
        .reduce(|a, b| vm_core::crypto::hash::Rpo256::merge(&[a, b]))
        .unwrap()
}

#[cfg(feature = "std")]
mod use_std_library {
    use std::{fs, io, path::Path};

    use miette::Report;
    use vm_core::utils::ReadAdapter;

    use super::*;
    use crate::Assembler;

    impl Library {
        /// File extension for the Assembly Library.
        pub const LIBRARY_EXTENSION: &'static str = "masl";

        /// Write the library to a target file
        ///
        /// NOTE: It is up to the caller to use the correct file extension, but there is no
        /// specific requirement that the extension be set, or the same as
        /// [`Self::LIBRARY_EXTENSION`].
        pub fn write_to_file(&self, path: impl AsRef<Path>) -> io::Result<()> {
            let path = path.as_ref();

            if let Some(dir) = path.parent() {
                fs::create_dir_all(dir)?;
            }

            // NOTE: We catch panics due to i/o errors here due to the fact that the ByteWriter
            // trait does not provide fallible APIs, so WriteAdapter will panic if the underlying
            // writes fail. This needs to be addressed in winterfell at some point
            std::panic::catch_unwind(|| {
                let mut file = fs::File::create(path)?;
                self.write_into(&mut file);
                Ok(())
            })
            .map_err(|p| {
                match p.downcast::<io::Error>() {
                    // SAFETY: It is guaranteed safe to read Box<std::io::Error>
                    Ok(err) => unsafe { core::ptr::read(&*err) },
                    Err(err) => std::panic::resume_unwind(err),
                }
            })?
        }

        /// Create a [Library] from a standard Miden Assembly project layout.
        ///
        /// The standard layout dictates that a given path is the root of a namespace, and the
        /// directory hierarchy corresponds to the namespace hierarchy. A `.masm` file found in a
        /// given subdirectory of the root, will be parsed with its [LibraryPath] set based on
        /// where it resides in the directory structure.
        ///
        /// This function recursively parses the entire directory structure under `path`, ignoring
        /// any files which do not have the `.masm` extension.
        ///
        /// For example, let's say I call this function like so:
        ///
        /// ```rust
        /// use std::sync::Arc;
        ///
        /// use miden_assembly::{Assembler, Library, LibraryNamespace};
        /// use vm_core::debuginfo::DefaultSourceManager;
        ///
        /// Library::from_dir(
        ///     "~/masm/std",
        ///     LibraryNamespace::new("std").unwrap(),
        ///     Assembler::new(Arc::new(DefaultSourceManager::default())),
        /// );
        /// ```
        ///
        /// Here's how we would handle various files under this path:
        ///
        /// - ~/masm/std/sys.masm            -> Parsed as "std::sys"
        /// - ~/masm/std/crypto/hash.masm    -> Parsed as "std::crypto::hash"
        /// - ~/masm/std/math/u32.masm       -> Parsed as "std::math::u32"
        /// - ~/masm/std/math/u64.masm       -> Parsed as "std::math::u64"
        /// - ~/masm/std/math/README.md      -> Ignored
        pub fn from_dir(
            path: impl AsRef<Path>,
            namespace: LibraryNamespace,
            assembler: Assembler,
        ) -> Result<Self, Report> {
            let path = path.as_ref();

            let modules =
                crate::parser::read_modules_from_dir(namespace, path, &assembler.source_manager())?;
            assembler.assemble_library(modules)
        }

        pub fn deserialize_from_file(path: impl AsRef<Path>) -> Result<Self, DeserializationError> {
            let path = path.as_ref();
            let mut file = fs::File::open(path).map_err(|err| {
                DeserializationError::InvalidValue(format!(
                    "failed to open file at {}: {err}",
                    path.to_string_lossy()
                ))
            })?;
            let mut adapter = ReadAdapter::new(&mut file);

            Self::read_from(&mut adapter)
        }
    }
}

// KERNEL LIBRARY
// ================================================================================================

/// Represents a library containing a Miden VM kernel.
///
/// This differs from the regular [Library] as follows:
/// - All exported procedures must be exported directly from the kernel namespace (i.e., `#sys`).
/// - There must be at least one exported procedure.
/// - The number of exported procedures cannot exceed [Kernel::MAX_NUM_PROCEDURES] (i.e., 256).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelLibrary {
    kernel: Kernel,
    kernel_info: ModuleInfo,
    library: Library,
}

impl AsRef<Library> for KernelLibrary {
    #[inline(always)]
    fn as_ref(&self) -> &Library {
        &self.library
    }
}

impl KernelLibrary {
    /// Returns the [Kernel] for this kernel library.
    pub fn kernel(&self) -> &Kernel {
        &self.kernel
    }

    /// Returns a reference to the inner [`MastForest`].
    pub fn mast_forest(&self) -> &Arc<MastForest> {
        self.library.mast_forest()
    }

    /// Destructures this kernel library into individual parts.
    pub fn into_parts(self) -> (Kernel, ModuleInfo, Arc<MastForest>) {
        (self.kernel, self.kernel_info, self.library.mast_forest)
    }
}

impl TryFrom<Library> for KernelLibrary {
    type Error = LibraryError;

    fn try_from(library: Library) -> Result<Self, Self::Error> {
        let kernel_path = LibraryPath::from(LibraryNamespace::Kernel);
        let mut proc_digests = Vec::with_capacity(library.exports.len());

        let mut kernel_module = ModuleInfo::new(kernel_path.clone());

        for (proc_path, &proc_node_id) in library.exports.iter() {
            // make sure all procedures are exported only from the kernel root
            if proc_path.module != kernel_path {
                return Err(LibraryError::InvalidKernelExport {
                    procedure_path: proc_path.clone(),
                });
            }

            let proc_digest = library.mast_forest[proc_node_id].digest();
            proc_digests.push(proc_digest);
            kernel_module.add_procedure(proc_path.name.clone(), proc_digest);
        }

        let kernel = Kernel::new(&proc_digests).map_err(LibraryError::KernelConversion)?;

        Ok(Self {
            kernel,
            kernel_info: kernel_module,
            library,
        })
    }
}

impl Serializable for KernelLibrary {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { kernel: _, kernel_info: _, library } = self;

        library.write_into(target);
    }
}

impl Deserializable for KernelLibrary {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let library = Library::read_from(source)?;

        Self::try_from(library).map_err(|err| {
            DeserializationError::InvalidValue(format!(
                "Failed to deserialize kernel library: {err}"
            ))
        })
    }
}

#[cfg(feature = "std")]
mod use_std_kernel {
    use std::{io, path::Path};

    use super::*;
    use crate::{diagnostics::Report, Assembler};

    impl KernelLibrary {
        /// Write the library to a target file
        pub fn write_to_file(&self, path: impl AsRef<Path>) -> io::Result<()> {
            self.library.write_to_file(path)
        }

        /// Create a [KernelLibrary] from a standard Miden Assembly kernel project layout.
        ///
        /// The kernel library will export procedures defined by the module at `sys_module_path`.
        /// If the optional `lib_dir` is provided, all modules under this directory will be
        /// available from the kernel module under the `kernel` namespace. For example, if
        /// `lib_dir` is set to "~/masm/lib", the files will be accessible in the kernel module as
        /// follows:
        ///
        /// - ~/masm/lib/foo.masm        -> Can be imported as "kernel::foo"
        /// - ~/masm/lib/bar/baz.masm    -> Can be imported as "kernel::bar::baz"
        ///
        /// Note: this is a temporary structure which will likely change once
        /// <https://github.com/0xPolygonMiden/miden-vm/issues/1436> is implemented.
        pub fn from_dir(
            sys_module_path: impl AsRef<Path>,
            lib_dir: Option<impl AsRef<Path>>,
            mut assembler: Assembler,
        ) -> Result<Self, Report> {
            // if library directory is provided, add modules from this directory to the assembler
            if let Some(lib_dir) = lib_dir {
                let lib_dir = lib_dir.as_ref();
                let namespace = LibraryNamespace::new("kernel").expect("invalid namespace");
                assembler.add_modules_from_dir(namespace, lib_dir)?;
            }

            assembler.assemble_kernel(sys_module_path.as_ref())
        }
    }
}
