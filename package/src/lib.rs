//! The [Package] containing a [vm_core::Program] or [assembly::Library] and a manifest(exports and
//! dependencies).

#![no_std]

extern crate alloc;

mod de;
mod dep;
mod package;
mod se;

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;

pub use self::{
    dep::{
        resolver::{
            DependencyResolver, LocalResolvedDependency, MemDependencyResolverByDigest,
            ResolvedDependency,
        },
        Dependency, DependencyName,
    },
    package::{MastArtifact, Package, PackageExport, PackageManifest},
};

type Digest = vm_core::chiplets::hasher::Digest;
