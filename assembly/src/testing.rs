use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::fmt;

use vm_core::Program;

#[cfg(feature = "std")]
use crate::diagnostics::reporting::set_panic_hook;
use crate::{
    assembler::Assembler,
    ast::{Form, Module, ModuleKind},
    diagnostics::{
        reporting::{set_hook, ReportHandlerOpts},
        Report, SourceFile, SourceManager,
    },
    library::Library,
    Compile, CompileOptions, LibraryPath, RpoDigest,
};

/// Represents a pattern for matching text abstractly
/// for use in asserting contents of complex diagnostics
#[derive(Debug)]
pub enum Pattern {
    /// Searches for an exact match of the given literal in the input string
    Literal(alloc::borrow::Cow<'static, str>),
    /// Searches for a match of the given regular expression in the input string
    Regex(regex::Regex),
}
impl Pattern {
    /// Construct a [Pattern] representing the given regular expression
    #[track_caller]
    pub fn regex(pattern: impl AsRef<str>) -> Self {
        Self::Regex(regex::Regex::new(pattern.as_ref()).expect("invalid regex"))
    }

    /// Check if this pattern matches `input`
    pub fn is_match(&self, input: impl AsRef<str>) -> bool {
        match self {
            Self::Literal(pattern) => input.as_ref().contains(pattern.as_ref()),
            Self::Regex(ref regex) => regex.is_match(input.as_ref()),
        }
    }

    /// Assert that this pattern matches `input`.
    ///
    /// This behaves like `assert_eq!` or `assert_matches!`, i.e. it
    /// will produce a helpful panic message on failure that renders
    /// the difference between what the pattern expected, and what
    /// it actually was matched against.
    #[track_caller]
    pub fn assert_match(&self, input: impl AsRef<str>) {
        let input = input.as_ref();
        if !self.is_match(input) {
            panic!(
                r"expected string was not found in emitted diagnostics:
expected input to {expected}
matched against: `{actual}`
",
                expected = self,
                actual = input
            );
        }
    }

    /// Like [Pattern::assert_match], but renders additional context
    /// in the case of failure to aid in troubleshooting.
    #[track_caller]
    pub fn assert_match_with_context(&self, input: impl AsRef<str>, context: impl AsRef<str>) {
        let input = input.as_ref();
        let context = context.as_ref();
        if !self.is_match(input) {
            panic!(
                r"expected string was not found in emitted diagnostics:
expected input to {expected}
matched against: `{actual}`
full output: `{context}`
",
                expected = self,
                actual = input
            );
        }
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Literal(ref lit) => write!(f, "contain `{}`", lit),
            Self::Regex(ref pat) => write!(f, "match regular expression `{}`", pat.as_str()),
        }
    }
}

impl From<&'static str> for Pattern {
    fn from(s: &'static str) -> Self {
        Self::Literal(alloc::borrow::Cow::Borrowed(s.trim()))
    }
}

impl From<String> for Pattern {
    fn from(s: String) -> Self {
        Self::Literal(alloc::borrow::Cow::Owned(s))
    }
}

impl From<regex::Regex> for Pattern {
    fn from(pat: regex::Regex) -> Self {
        Self::Regex(pat)
    }
}

/// Create a [Pattern::Regex] from the given input
#[macro_export]
macro_rules! regex {
    ($source:literal) => {
        Pattern::regex($source)
    };

    ($source:expr) => {
        Pattern::regex($source)
    };
}

/// Construct an [`Arc<SourceFile>`] from a string literal or expression,
/// such that emitted diagnostics reference the file and line on which
/// the source file was constructed.
#[macro_export]
macro_rules! source_file {
    ($context:expr, $source:literal) => {
        $context.source_manager().load(concat!("test", line!()), $source.to_string())
    };
    ($context:expr, $source:expr) => {
        $context.source_manager().load(concat!("test", line!()), $source.to_string())
    };
}

/// Assert that the given diagnostic/error value, when rendered to stdout,
/// contains the given pattern
#[macro_export]
macro_rules! assert_diagnostic {
    ($diagnostic:expr, $expected:literal) => {{
        let actual = format!("{}", PrintDiagnostic::new_without_color($diagnostic));
        Pattern::from($expected).assert_match(actual);
    }};

    ($diagnostic:expr, $expected:expr) => {{
        let actual = format!("{}", PrintDiagnostic::new_without_color($diagnostic));
        Pattern::from($expected).assert_match(actual);
    }};
}

/// Like [assert_diagnostic], but matches each non-empty line of the rendered output to a
/// corresponding pattern.
///
/// So if the output has 3 lines, the second of which is empty, and you provide 2 patterns, the
/// assertion passes if the first line matches the first pattern, and the third line matches the
/// second pattern - the second line is ignored because it is empty.
#[macro_export]
macro_rules! assert_diagnostic_lines {
    ($diagnostic:expr, $($expected:expr),+) => {{
        let actual = format!("{}", $crate::diagnostics::reporting::PrintDiagnostic::new_without_color($diagnostic));
        let lines = actual.lines().filter(|l| !l.trim().is_empty()).zip([$(Pattern::from($expected)),*].into_iter());
        for (actual_line, expected) in lines {
            expected.assert_match_with_context(actual_line, &actual);
        }
    }};
}

#[macro_export]
macro_rules! parse_module {
    ($context:expr, $path:literal, $source:expr) => {{
        let path = $crate::LibraryPath::new($path).expect("invalid library path");
        let source_file = $context
            .source_manager()
            .load(concat!("test", line!()), alloc::string::String::from($source));
        $crate::ast::Module::parse(path, $crate::ast::ModuleKind::Library, source_file)
            .expect("failed to parse module")
    }};
}

/// A [TestContext] provides common functionality for all tests which interact with an [Assembler].
///
/// It is used by constructing it with `TestContext::default()`, which will initialize the
/// diagnostic reporting infrastructure, and construct a default [Assembler] instance for you. You
/// can then optionally customize the context, or start invoking any of its test helpers.
///
/// Some of the assertion macros defined above require a [TestContext], so be aware of that.
pub struct TestContext {
    source_manager: Arc<dyn SourceManager>,
    assembler: Assembler,
}

impl Default for TestContext {
    fn default() -> Self {
        Self::new()
    }
}

impl TestContext {
    pub fn new() -> Self {
        #[cfg(feature = "std")]
        {
            let result = set_hook(Box::new(|_| Box::new(ReportHandlerOpts::new().build())));
            #[cfg(feature = "std")]
            if result.is_ok() {
                set_panic_hook();
            }
        }

        #[cfg(not(feature = "std"))]
        {
            let _ = set_hook(Box::new(|_| Box::new(ReportHandlerOpts::new().build())));
        }
        let source_manager = Arc::new(crate::DefaultSourceManager::default());
        // Note: we do not set debug mode by default because we do not want AsmOp decorators to be
        // inserted in our programs
        let assembler = Assembler::new(source_manager.clone()).with_warnings_as_errors(true);
        Self { source_manager, assembler }
    }

    pub fn with_debug_info(mut self, yes: bool) -> Self {
        self.assembler.set_debug_mode(yes);
        self
    }

    #[inline(always)]
    pub fn source_manager(&self) -> Arc<dyn SourceManager> {
        self.source_manager.clone()
    }

    /// Parse the given source file into a vector of top-level [Form]s.
    ///
    /// This does not run semantic analysis, or construct a [Module] from the parsed
    /// forms, and is largely intended for low-level testing of the parser.
    #[track_caller]
    pub fn parse_forms(&self, source: Arc<SourceFile>) -> Result<Vec<Form>, Report> {
        crate::parser::parse_forms(source.clone())
            .map_err(|err| Report::new(err).with_source_code(source))
    }

    /// Parse the given source file into an executable [Module].
    ///
    /// This runs semantic analysis, and the returned module is guaranteed to be syntactically
    /// valid.
    #[track_caller]
    pub fn parse_program(&self, source: impl Compile) -> Result<Box<Module>, Report> {
        source.compile_with_options(
            self.source_manager.as_ref(),
            CompileOptions {
                warnings_as_errors: self.assembler.warnings_as_errors(),
                ..Default::default()
            },
        )
    }

    /// Parse the given source file into a kernel [Module].
    ///
    /// This runs semantic analysis, and the returned module is guaranteed to be syntactically
    /// valid.
    #[allow(unused)]
    #[track_caller]
    pub fn parse_kernel(&self, source: impl Compile) -> Result<Box<Module>, Report> {
        source.compile_with_options(
            self.source_manager.as_ref(),
            CompileOptions {
                warnings_as_errors: self.assembler.warnings_as_errors(),
                ..CompileOptions::for_kernel()
            },
        )
    }

    /// Parse the given source file into an anonymous library [Module].
    ///
    /// This runs semantic analysis, and the returned module is guaranteed to be syntactically
    /// valid.
    #[track_caller]
    pub fn parse_module(&self, source: impl Compile) -> Result<Box<Module>, Report> {
        source.compile_with_options(
            self.source_manager.as_ref(),
            CompileOptions {
                warnings_as_errors: self.assembler.warnings_as_errors(),
                ..CompileOptions::for_library()
            },
        )
    }

    /// Parse the given source file into a library [Module] with the given fully-qualified path.
    #[track_caller]
    pub fn parse_module_with_path(
        &self,
        path: LibraryPath,
        source: impl Compile,
    ) -> Result<Box<Module>, Report> {
        source.compile_with_options(
            self.source_manager.as_ref(),
            CompileOptions {
                warnings_as_errors: self.assembler.warnings_as_errors(),
                ..CompileOptions::new(ModuleKind::Library, path).unwrap()
            },
        )
    }

    /// Add `module` to the [Assembler] constructed by this context, making it available to
    /// other modules.
    #[track_caller]
    pub fn add_module(&mut self, module: impl Compile) -> Result<(), Report> {
        self.assembler.add_module(module).map(|_| ())
    }

    /// Add a module to the [Assembler] constructed by this context, with the fully-qualified
    /// name `path`, by parsing it from the provided source file.
    ///
    /// This will fail if the module cannot be parsed, fails semantic analysis, or conflicts
    /// with a previously added module within the assembler.
    #[track_caller]
    pub fn add_module_from_source(
        &mut self,
        path: LibraryPath,
        source: impl Compile,
    ) -> Result<(), Report> {
        self.assembler
            .add_module_with_options(
                source,
                CompileOptions {
                    path: Some(path),
                    ..CompileOptions::for_library()
                },
            )
            .map(|_| ())
    }

    /// Add the modules of `library` to the [Assembler] constructed by this context.
    #[track_caller]
    pub fn add_library(&mut self, library: impl AsRef<Library>) -> Result<(), Report> {
        self.assembler.add_library(library)
    }

    /// Compile a [Program] from `source` using the [Assembler] constructed by this context.
    ///
    /// NOTE: Any modules added by, e.g. `add_module`, will be available to the executable
    /// module represented in `source`.
    #[track_caller]
    pub fn assemble(&self, source: impl Compile) -> Result<Program, Report> {
        self.assembler.clone().assemble_program(source)
    }

    /// Compile a [Library] from `modules` using the [Assembler] constructed by this
    /// context.
    ///
    /// NOTE: Any modules added by, e.g. `add_module`, will be available to the library
    #[track_caller]
    pub fn assemble_library(
        &self,
        modules: impl IntoIterator<Item = Box<Module>>,
    ) -> Result<Library, Report> {
        self.assembler.clone().assemble_library(modules)
    }

    /// Compile a module from `source`, with the fully-qualified name `path`, to MAST, returning
    /// the MAST roots of all the exported procedures of that module.
    #[track_caller]
    pub fn assemble_module(
        &self,
        _path: LibraryPath,
        _module: impl Compile,
    ) -> Result<Vec<RpoDigest>, Report> {
        // This API will change after we implement `Assembler::add_library()`
        unimplemented!()
    }
}
