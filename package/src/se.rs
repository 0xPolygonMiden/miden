use alloc::vec;

use vm_core::utils::Serializable;

use crate::{package::MastArtifact, Digest};

/// Serialize a [Digest] into a byte array
pub fn serialize_digest<S>(digest: &Digest, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serde_bytes::serialize(&digest.as_bytes(), serializer)
}

/// Serialize a [MastArtifact] into a byte array
pub fn serialize_mast<S>(mast: &MastArtifact, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut buffer = vec![];
    match mast {
        MastArtifact::Executable(program) => {
            buffer.extend(b"PRG\0");
            program.write_into(&mut buffer);
        },
        MastArtifact::Library(library) => {
            buffer.extend(b"LIB\0");
            library.write_into(&mut buffer);
        },
    }

    serde_bytes::serialize(&buffer, serializer)
}
