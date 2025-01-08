# Miden Assembly

This crate contains Miden assembler.

The purpose of the assembler is to compile/assemble [Miden Assembly (MASM)](https://0xpolygonmiden.github.io/miden-vm/user_docs/assembly/main.html)
source code into a Miden VM program (represented by `Program` struct). The program
can then be executed on Miden VM [processor](../processor).

## Compiling Miden Assembly

To assemble a program for the Miden VM from some Miden Assembly source code, you first
need to instantiate the assembler, and then call one of its provided assembly methods,
e.g. `assemble`.

The `assemble` method takes the source code of an executable module as a string, or
file path, and either compiles it to a `Program`, or returns an error if the program
is invalid in some way. The error type returned can be pretty-printed to show rich
diagnostics about the source code from which an error is derived, when applicable,
much like the Rust compiler.

### Example

```rust
use std::path::Path;
use miden_assembly::Assembler;

// Instantiate a default, empty assembler
let assembler = Assembler::default();

// Example 1: Simple arithmetic
let program = assembler
    .assemble_program("begin push.3 push.5 add end")
    .unwrap();

// Example 2: Loading from file (requires the `std` feature)
let program = assembler
    .assemble_program(&Path::new("./example.masm"))
    .unwrap();
```

> [!IMPORTANT]  
> The default assembler provides no kernel or standard libraries. You must
> explicitly add those using the various builder methods of `Assembler`.

## Assembler Options

As noted above, the default assembler is instantiated with nothing in it but
the source code you provide. If you want to support more complex programs, you
will want to factor code into libraries and modules, and then link all of them
together at once. This can be acheived using a set of builder methods of the
`Assembler` struct, e.g. `with_kernel_from_module`, `with_library`, etc.

We'll look at a few of these in more detail below. See the module documentation
for the full set of APIs and how to use them.

### Libraries

The first use case that you are likely to encounter is the desire to factor out
some shared code into a _library_. A library is a set of modules which belong
to a common namespace, and which are packaged together. The
[standard library](../stdlib) is an example of this.

To call code in this library from your program entrypoint, you must add the
library to the instance of the assembler you will compile the program with,
using the `with_library` or `with_libraries` methods.

To be a bit more precise, a library can be anything that implements the `Library`
trait, allowing for some flexibility in how they are managed. The standard library
referenced above implements this trait, so if we wanted to make use of the Miden
standard library in our own program, we would add it like so:

```rust
use miden_assembly::Assembler;

let assembler = Assembler::default()
    .with_library(&miden_stdlib::StdLibrary::default())
    .unwrap();
```

The resulting assembler can now compile code that invokes any of the
standard library procedures by importing them from the namespace of
the library, as shown next:

```
use.std::math::u64

begin
    push.1.0
    push.2.0
    exec.u64::wrapping_add
end
```

A generic container format for libraries, which implements `Library` and
can be used for any set of Miden assembly modules belonging to the same
namespace, is provided by the `MaslLibrary` struct.

A `MaslLibrary` serializes/deserializes to the `.masl` file format, which
is a binary format containing the parsed, but uncompiled, Miden Assembly
code in the form of its abstract syntax tree. You can construct and load
`.masl` files using the `MaslLibrary` interface.

### Program Kernels

A _program kernel_ defines a set of procedures which can be invoked via
`syscall` instructions. Miden programs are always compiled against some kernel,
and by default this kernel is empty, and so no `syscall` instructions are
allowed.

You can provide a kernel in one of two ways: a precompiled `Kernel` struct,
or by compiling a kernel module from source, as shown below:

```rust
use miden_assembly::Assembler;

let assembler = Assembler::default()
    .with_kernel_from_module("export.foo add end")
    .unwrap();
```

Programs compiled by this assembler will be able to make calls to the
`foo` procedure by executing the `syscall` instruction, like so:

```rust
assembler.assemble_program("
begin
    syscall.foo
end
").unwrap();
```

> [!NOTE]
> An unqualified `syscall` target is assumed to be defined in the kernel module.
> This is unlike the `exec` and `call` instructions, which require that callees
> resolve to a local procedure; a procedure defined in an explicitly imported
> module; or the hash of a MAST root corresponding to the compiled procedure.
>
> These options are also available to `syscall`, with the caveat that whatever
> method is used, it _must_ resolve to a procedure in the kernel specified to
> the assembler, or compilation will fail with an error.

### Debug Mode

The assembler can be instantiated in debug mode. Compiling a program with such an assembler retains source mappings between assembly instructions and VM operations. Thus, when such a program is executed using the `execute_iter()` function of the [processor](../processor), it is possible to correlate each
instruction with the source code that it is derived from. You can do this as
shown below:

```rust
use miden_assembly::Assembler;

// Instantiate the assembler in debug mode
let assembler = Assembler::default().with_debug_mode(true);
```

### Testing Your Programs

To test your Miden Assembly programs, you can use the following approaches:

```rust
use miden_assembly::Assembler;

#[test]
fn test_simple_program() {
    let assembler = Assembler::default();
    
    // Test program compilation
    let program = assembler
        .assemble_program("begin push.1 push.2 add end")
        .expect("Failed to compile program");
        
    // Additional test assertions...
}
```

For more examples and testing strategies, see:
- [Testing Guide](../docs/testing.md)
- [Example Programs](../examples/)

## Putting it all together

To help illustrate how all of the topics we discussed above can be combined
together, let's look at one last example:

```rust
use miden_assembly::Assembler;
use miden_stdlib::StdLibrary;

// Source code of the kernel module
let kernel = "export.foo add end";

// Instantiate the assembler with multiple options at once
let assembler = Assembler::default()
    .with_debug_mode(true)
    .with_library(&StdLibrary::default())
    .and_then(|a| a.with_kernel_from_module(kernel))
    .unwrap();

// Assemble our program
assembler.assemble_program("
begin
    push.1.2
    syscall.foo
end
");
```

## License

This project is [MIT licensed](../LICENSE).
