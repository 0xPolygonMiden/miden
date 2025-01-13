use std::{path::PathBuf, time::Instant};

use assembly::diagnostics::{IntoDiagnostic, Report, WrapErr};
use clap::Parser;
use miden_vm::internal::InputFile;
use processor::{DefaultHost, ExecutionOptions, ExecutionTrace};
use stdlib::StdLibrary;
use tracing::instrument;

use super::data::{Libraries, OutputFile, ProgramFile};

#[derive(Debug, Clone, Parser)]
#[clap(about = "Run a miden program")]
pub struct RunCmd {
    /// Path to .masm assembly file
    #[clap(short = 'a', long = "assembly", value_parser)]
    assembly_file: PathBuf,

    /// Number of cycles the program is expected to consume
    #[clap(short = 'e', long = "exp-cycles", default_value = "64")]
    expected_cycles: u32,

    /// Path to input file
    #[clap(short = 'i', long = "input", value_parser)]
    input_file: Option<PathBuf>,

    /// Paths to .masl library files
    #[clap(short = 'l', long = "libraries", value_parser)]
    library_paths: Vec<PathBuf>,

    /// Maximum number of cycles a program is allowed to consume
    #[clap(short = 'm', long = "max-cycles", default_value = "4294967295")]
    max_cycles: u32,

    /// Number of outputs
    #[clap(short = 'n', long = "num-outputs", default_value = "16")]
    num_outputs: usize,

    /// Path to output file
    #[clap(short = 'o', long = "output", value_parser)]
    output_file: Option<PathBuf>,

    /// Enable tracing to monitor execution of the VM
    #[clap(short = 't', long = "trace")]
    trace: bool,

    /// Enable debug instructions
    #[clap(short = 'd', long = "debug")]
    debug: bool,
}

impl RunCmd {
    pub fn execute(&self) -> Result<(), Report> {
        println!("===============================================================================");
        println!("Run program: {}", self.assembly_file.display());
        println!("-------------------------------------------------------------------------------");

        let now = Instant::now();

        let (trace, program_hash) = run_program(self)?;

        println!(
            "Executed the program with hash {} in {} ms",
            hex::encode(program_hash),
            now.elapsed().as_millis()
        );

        if let Some(output_path) = &self.output_file {
            // write outputs to file if one was specified
            OutputFile::write(trace.stack_outputs(), output_path).map_err(Report::msg)?;
        } else {
            // write the stack outputs to the screen.
            println!("Output: {:?}", trace.stack_outputs().stack_truncated(self.num_outputs));
        }

        // calculate the percentage of padded rows
        let padding_percentage = (trace.trace_len_summary().padded_trace_len()
            - trace.trace_len_summary().trace_len())
            * 100
            / trace.trace_len_summary().padded_trace_len();
        // print the required cycles for each component
        println!(
            "VM cycles: {} extended to {} steps ({}% padding).
├── Stack rows: {}
├── Range checker rows: {}
└── Chiplets rows: {}
    ├── Hash chiplet rows: {}
    ├── Bitwise chiplet rows: {}
    ├── Memory chiplet rows: {}
    └── Kernel ROM rows: {}",
            trace.trace_len_summary().trace_len(),
            trace.trace_len_summary().padded_trace_len(),
            padding_percentage,
            trace.trace_len_summary().main_trace_len(),
            trace.trace_len_summary().range_trace_len(),
            trace.trace_len_summary().chiplets_trace_len().trace_len(),
            trace.trace_len_summary().chiplets_trace_len().hash_chiplet_len(),
            trace.trace_len_summary().chiplets_trace_len().bitwise_chiplet_len(),
            trace.trace_len_summary().chiplets_trace_len().memory_chiplet_len(),
            trace.trace_len_summary().chiplets_trace_len().kernel_rom_len(),
        );

        Ok(())
    }
}

// HELPER FUNCTIONS
// ================================================================================================

#[instrument(name = "run_program", skip_all)]
fn run_program(params: &RunCmd) -> Result<(ExecutionTrace, [u8; 32]), Report> {
    for lib in &params.library_paths {
        if !lib.is_file() {
            let name = lib.display();
            return Err(Report::msg(format!("{name} must be a file.")));
        };
    }

    // load libraries from files
    let libraries = Libraries::new(&params.library_paths)?;

    // load program from file and compile
    let program = ProgramFile::read(&params.assembly_file)?
        .compile(params.debug.into(), &libraries.libraries)?;

    // load input data from file
    let input_data = InputFile::read(&params.input_file, &params.assembly_file)?;

    let execution_options = ExecutionOptions::new(
        Some(params.max_cycles),
        params.expected_cycles,
        params.trace,
        params.debug,
    )
    .into_diagnostic()?;

    // fetch the stack and program inputs from the arguments
    let stack_inputs = input_data.parse_stack_inputs().map_err(Report::msg)?;
    let mut host = DefaultHost::new(input_data.parse_advice_provider().map_err(Report::msg)?);
    host.load_mast_forest(StdLibrary::default().mast_forest().clone()).unwrap();
    for lib in libraries.libraries {
        host.load_mast_forest(lib.mast_forest().clone()).unwrap();
    }

    let program_hash: [u8; 32] = program.hash().into();

    // execute program and generate outputs
    let trace = processor::execute(&program, stack_inputs, &mut host, execution_options)
        .into_diagnostic()
        .wrap_err("Failed to generate execution trace")?;

    Ok((trace, program_hash))
}
