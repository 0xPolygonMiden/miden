use alloc::{fmt, sync::Arc};

use assembly::Library;
use vm_core::{utils::Deserializable, Program};

use crate::{package::MastArtifact, Digest};

/// Deserialize a [Digest] from a byte array
pub fn deserialize_digest<'de, D>(deserializer: D) -> Result<Digest, D::Error>
where
    D: serde::Deserializer<'de>,
{
    const DIGEST_BYTES: usize = 32;

    let bytes: [u8; DIGEST_BYTES] = serde_bytes::deserialize(deserializer)?;

    Digest::try_from(bytes).map_err(serde::de::Error::custom)
}

/// Deserialize a [MastArtifact] from a byte array
pub fn deserialize_mast<'de, D>(deserializer: D) -> Result<MastArtifact, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct MastArtifactVisitor;

    impl serde::de::Visitor<'_> for MastArtifactVisitor {
        type Value = MastArtifact;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("mast artifact")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if let Some(bytes) = v.strip_prefix(b"PRG\0") {
                Program::read_from_bytes(bytes)
                    .map(Arc::new)
                    .map(MastArtifact::Executable)
                    .map_err(serde::de::Error::custom)
            } else if let Some(bytes) = v.strip_prefix(b"LIB\0") {
                Library::read_from_bytes(bytes)
                    .map(Arc::new)
                    .map(MastArtifact::Library)
                    .map_err(serde::de::Error::custom)
            } else {
                Err(serde::de::Error::invalid_value(
                    serde::de::Unexpected::Bytes(v.get(0..4).unwrap_or(v)),
                    &"expected valid mast artifact type tag",
                ))
            }
        }
    }
    deserializer.deserialize_bytes(MastArtifactVisitor)
}
