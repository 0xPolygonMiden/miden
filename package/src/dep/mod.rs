use alloc::string::String;

use serde::{Deserialize, Serialize};

use super::{de, se};
use crate::Digest;

pub(crate) mod resolver;

/// The name of a dependency
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, derive_more::From)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct DependencyName(String);

/// A package dependency
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct Dependency {
    /// The name of the dependency.
    /// Serves as a human-readable identifier for the dependency and a search hint for the resolver
    pub name: DependencyName,
    /// The digest of the dependency.
    /// Serves as an ultimate source of truth for identifying the dependency.
    #[serde(
        serialize_with = "se::serialize_digest",
        deserialize_with = "de::deserialize_digest"
    )]
    #[cfg_attr(test, proptest(value = "Digest::default()"))]
    pub digest: Digest,
}
