use alloc::{collections::BTreeSet, format, string::String, sync::Arc, vec::Vec};
use core::fmt;

use assembly::{ast::QualifiedProcedureName, Library, Report};
use serde::{Deserialize, Serialize};
use vm_core::{mast::MastForest, utils::DisplayHex, Program};

use super::{de, se};
use crate::{Dependency, Digest};

// MAST ARTIFACT
// ================================================================================================

/// The artifact produced by lowering a program or library to a Merkelized Abstract Syntax Tree
///
/// This type is used in compilation pipelines to abstract over the type of output requested.
#[derive(Debug, Clone, Eq, PartialEq, derive_more::From)]
pub enum MastArtifact {
    /// A MAST artifact which can be executed by the VM directly
    Executable(Arc<Program>),
    /// A MAST artifact which can be used as a dependency by a [Program]
    Library(Arc<Library>),
}

impl MastArtifact {
    /// Get the underlying [Program] for this artifact, or panic if this is a [Library]
    pub fn unwrap_program(self) -> Arc<Program> {
        match self {
            Self::Executable(prog) => prog,
            Self::Library(_) => panic!("attempted to unwrap 'mast' library as program"),
        }
    }

    /// Get the underlying [Library] for this artifact, or panic if this is a [Program]
    pub fn unwrap_library(self) -> Arc<Library> {
        match self {
            Self::Executable(_) => panic!("attempted to unwrap 'mast' program as library"),
            Self::Library(lib) => lib,
        }
    }

    /// Get the content digest associated with this artifact
    pub fn digest(&self) -> Digest {
        match self {
            Self::Executable(ref prog) => prog.hash(),
            Self::Library(ref lib) => *lib.digest(),
        }
    }

    /// Get the underlying [MastForest] for this artifact
    pub fn mast_forest(&self) -> &MastForest {
        match self {
            Self::Executable(ref prog) => prog.mast_forest(),
            Self::Library(ref lib) => lib.mast_forest(),
        }
    }
}

// PACKAGE MANIFEST
// ================================================================================================

/// The manifest of a package, containing the set of package dependencies (libraries or packages)
/// and exported procedures and their signatures, if known.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct PackageManifest {
    /// The set of exports in this package.
    pub exports: BTreeSet<PackageExport>,
    /// The libraries (packages) linked against by this package, which must be provided when
    /// executing the program.
    pub dependencies: Vec<Dependency>,
}

/// A procedure exported by a package, along with its digest and
/// signature(will be added after MASM type attributes are implemented).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct PackageExport {
    /// The fully-qualified name of the procedure exported by this package
    pub name: String,
    /// The digest of the procedure exported by this package
    #[serde(
        serialize_with = "se::serialize_digest",
        deserialize_with = "de::deserialize_digest"
    )]
    #[cfg_attr(test, proptest(value = "Digest::default()"))]
    pub digest: Digest,
}

impl fmt::Debug for PackageExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { name, digest } = self;
        f.debug_struct("PackageExport")
            .field("name", &format_args!("{}", name))
            .field("digest", &format_args!("{}", DisplayHex::new(&digest.as_bytes())))
            .finish()
    }
}

// PACKAGE
// ================================================================================================

/// A package containing a [Program]/[Library], and a manifest (exports and dependencies).
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct Package {
    /// Name of the package
    pub name: String,
    /// The MAST artifact ([Program] or [Library]) of the package
    #[serde(serialize_with = "se::serialize_mast", deserialize_with = "de::deserialize_mast")]
    pub mast: MastArtifact,
    /// The package manifest, containing the set of exported procedures and their signatures,
    /// if known.
    pub manifest: PackageManifest,
}

impl Package {
    const MAGIC: &'static [u8] = b"MASP\0";
    const FORMAT_VERSION: &'static [u8] = b"1.0\0";

    /// Parses a package from the provided bytes
    pub fn read_from_bytes<B>(bytes: B) -> Result<Self, Report>
    where
        B: AsRef<[u8]>,
    {
        use alloc::borrow::Cow;

        let bytes = bytes.as_ref();

        let bytes = bytes
            .strip_prefix(Self::MAGIC)
            .ok_or_else(|| Report::msg("invalid package: missing header"))?;
        let bytes = bytes.strip_prefix(Self::FORMAT_VERSION).ok_or_else(|| {
            Report::msg(format!(
                "invalid package: incorrect version, expected '1.0', got '{}'",
                bytes.get(0..4).map(String::from_utf8_lossy).unwrap_or(Cow::Borrowed("")),
            ))
        })?;

        bitcode::deserialize(bytes).map_err(Report::msg)
    }

    /// Serializes the package into a byte array
    pub fn write_to_bytes(&self) -> Result<Vec<u8>, Report> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::MAGIC);
        bytes.extend_from_slice(Self::FORMAT_VERSION);
        let mut data = bitcode::serialize(self).map_err(Report::msg)?;
        bytes.append(&mut data);
        Ok(bytes)
    }

    pub fn digest(&self) -> Digest {
        self.mast.digest()
    }

    /// Checks if the package's MAST artifact is a [Program]
    pub fn is_program(&self) -> bool {
        matches!(self.mast, MastArtifact::Executable(_))
    }

    /// Checks if the package's MAST artifact is a [Library]
    pub fn is_library(&self) -> bool {
        matches!(self.mast, MastArtifact::Library(_))
    }

    /// Unwraps the package's MAST artifact as a [Program] or panics if it is a [Library]
    pub fn unwrap_program(&self) -> Arc<Program> {
        match self.mast {
            MastArtifact::Executable(ref prog) => Arc::clone(prog),
            _ => panic!("expected package to contain a program, but got a library"),
        }
    }

    /// Unwraps the package's MAST artifact as a [Library] or panics if it is a [Program]
    pub fn unwrap_library(&self) -> Arc<Library> {
        match self.mast {
            MastArtifact::Library(ref lib) => Arc::clone(lib),
            _ => panic!("expected package to contain a library, but got an executable"),
        }
    }

    /// Creates a new package with [Program] from this [Library] package and the given
    /// entrypoint (should be a procedure in the library).
    pub fn make_executable(&self, entrypoint: &QualifiedProcedureName) -> Result<Self, Report> {
        let MastArtifact::Library(ref library) = self.mast else {
            return Err(Report::msg("expected library but got an executable"));
        };

        let module = library
            .module_infos()
            .find(|info| info.path() == &entrypoint.module)
            .ok_or_else(|| {
                Report::msg(format!(
                    "invalid entrypoint: library does not contain a module named '{}'",
                    entrypoint.module
                ))
            })?;
        if let Some(digest) = module.get_procedure_digest_by_name(&entrypoint.name) {
            let node_id = library.mast_forest().find_procedure_root(digest).ok_or_else(|| {
                Report::msg(
                    "invalid entrypoint: malformed library - procedure exported, but digest has \
                     no node in the forest",
                )
            })?;

            let exports = BTreeSet::from_iter(self.manifest.exports.iter().find_map(|export| {
                if export.digest == digest {
                    Some(export.clone())
                } else {
                    None
                }
            }));

            Ok(Self {
                name: self.name.clone(),
                mast: MastArtifact::Executable(Arc::new(Program::new(
                    library.mast_forest().clone(),
                    node_id,
                ))),
                manifest: PackageManifest {
                    exports,
                    dependencies: self.manifest.dependencies.clone(),
                },
            })
        } else {
            Err(Report::msg(format!(
                "invalid entrypoint: library does not export '{}'",
                entrypoint
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, LazyLock};

    use assembly::{parse_module, testing::TestContext, Assembler, Library};
    use proptest::prelude::*;
    use vm_core::Program;

    use super::MastArtifact;

    impl Arbitrary for MastArtifact {
        type Parameters = ();

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop_oneof![Just(LIB_EXAMPLE.clone().into()), Just(PRG_EXAMPLE.clone().into())].boxed()
        }

        type Strategy = BoxedStrategy<Self>;
    }

    static LIB_EXAMPLE: LazyLock<Arc<Library>> = LazyLock::new(build_library_example);
    static PRG_EXAMPLE: LazyLock<Arc<Program>> = LazyLock::new(build_program_example);

    fn build_library_example() -> Arc<Library> {
        let context = TestContext::new();
        // declare foo module
        let foo = r#"
        export.foo
            add
        end
        export.foo_mul
            mul
        end
    "#;
        let foo = parse_module!(&context, "test::foo", foo);

        // declare bar module
        let bar = r#"
        export.bar
            mtree_get
        end
        export.bar_mul
            mul
        end
    "#;
        let bar = parse_module!(&context, "test::bar", bar);
        let modules = [foo, bar];

        // serialize/deserialize the bundle with locations
        Assembler::new(context.source_manager())
            .assemble_library(modules.iter().cloned())
            .expect("failed to assemble library")
            .into()
    }

    fn build_program_example() -> Arc<Program> {
        let source = "
    begin
        push.1.2
        add
        drop
    end
    ";
        let assembler = Assembler::default();
        assembler.assemble_program(source).unwrap().into()
    }
}
