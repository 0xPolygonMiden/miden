use super::Digest;
use core::fmt;

// PROXY BLOCK
// ================================================================================================
/// Block for a unknown function call.
///
/// Proxy blocks are used to verify the integrity of a program's hash while keeping parts
/// of the program secret. Fails if executed.
///
/// Hash of a proxy block is not computed but is rather defined at instantiation time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proxy {
    hash: Digest,
}

impl Proxy {
    /// Returns a new [Proxy] block instantiated with the specified code hash.
    pub fn new(code_hash: Digest) -> Self {
        Self { hash: code_hash }
    }

    /// Returns a hash of this code block.
    pub fn hash(&self) -> Digest {
        self.hash
    }
}

impl crate::prettier::PrettyPrint for Proxy {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;
        use miden_formatting::hex::DisplayHex;

        const_text("proxy") + const_text(".") + display(DisplayHex(&self.hash.as_bytes()))
    }
}

impl fmt::Display for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::prettier::PrettyPrint;
        self.pretty_print(f)
    }
}
