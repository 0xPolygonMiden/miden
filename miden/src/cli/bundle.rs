use std::path::PathBuf;

use assembly::{
    diagnostics::{IntoDiagnostic, Report},
    Assembler, KernelLibrary, Library, LibraryNamespace,
};
use clap::Parser;
use stdlib::StdLibrary;

#[derive(Debug, Clone, Parser)]
#[clap(
    name = "Compile Library",
    about = "Bundles .masm files into a single .masl library with access to the stdlib."
)]
pub struct BundleCmd {
    /// Include debug symbols.
    #[clap(short, long, action)]
    debug: bool,
    /// Path to a directory containing the `.masm` files which are part of the library.
    #[clap(value_parser)]
    dir: PathBuf,
    /// Defines the top-level namespace, e.g. `mylib`, otherwise the directory name is used. For a
    /// kernel library the namespace defaults to `kernel`.
    #[clap(short, long)]
    namespace: Option<String>,
    /// Version of the library, defaults to `0.1.0`.
    #[clap(short, long, default_value = "0.1.0")]
    version: String,
    /// Build a kernel library from module `kernel` and using the library `dir` as kernel
    /// namespace. The `kernel` file should not be in the directory `dir`.
    #[clap(short, long)]
    kernel: Option<PathBuf>,
    /// Path of the output `.masl` file.
    #[clap(short, long)]
    output: Option<PathBuf>,
}

impl BundleCmd {
    pub fn execute(&self) -> Result<(), Report> {
        println!("============================================================");
        println!("Build library");
        println!("============================================================");

        let mut assembler = Assembler::default().with_debug_mode(self.debug);

        if self.dir.is_file() {
            return Err(Report::msg("`dir` must be a directory."));
        }
        let dir = self.dir.file_name().ok_or("`dir` cannot end with `..`.").map_err(Report::msg)?;

        // write the masl output
        let output_file = match &self.output {
            Some(output) => output,
            None => {
                let parent =
                    &self.dir.parent().ok_or("Invalid output path").map_err(Report::msg)?;
                &parent.join("out").with_extension(Library::LIBRARY_EXTENSION)
            },
        };

        match &self.kernel {
            Some(kernel) => {
                if !kernel.is_file() {
                    return Err(Report::msg("`kernel` must be a file"));
                };
                assembler.add_library(StdLibrary::default())?;
                let library = KernelLibrary::from_dir(kernel, Some(&self.dir), assembler)?;
                library.write_to_file(output_file).into_diagnostic()?;
                println!(
                    "Built kernel module {} with library {}",
                    kernel.display(),
                    &self.dir.display()
                );
            },
            None => {
                let namespace = match &self.namespace {
                    Some(namespace) => namespace.to_string(),
                    None => dir.to_string_lossy().into_owned(),
                };
                let library_namespace = namespace.parse::<LibraryNamespace>()?;
                assembler.add_library(StdLibrary::default())?;
                let library = Library::from_dir(&self.dir, library_namespace, assembler)?;
                library.write_to_file(output_file).into_diagnostic()?;
                println!("Built library {}", namespace);
            },
        }

        Ok(())
    }
}
