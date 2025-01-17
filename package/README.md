## Overview

The `miden-package` crate provides the `Package` type, which represents a Miden package.
It contains a compiled `Library`/`Program` along with their exported functions and dependencies.

## Binary Format

The header contains the following fields:
- "MASP" magic bytes (4 bytes);
- Version of the package binary format (3 bytes, e.g. "1.0");

The header is followed by the `Package` serialized with `serde` using the [`bitcode`](https://docs.rs/bitcode/latest/bitcode/#structs) encoder to minimize the size.


## License

This project is [MIT licensed](../LICENSE).
