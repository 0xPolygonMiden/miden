use super::{
    AbsolutePath, BTreeMap, ParsingError, ProcedureName, String, ToString, Vec, MAX_PROC_NAME_LEN,
    MODULE_PATH_DELIM,
};
use core::fmt;

mod stream;
pub use stream::TokenStream;

// TOKEN
// ================================================================================================
/// TODO: add comments
#[derive(Clone, Debug, Default)]
pub struct Token<'a> {
    parts: Vec<&'a str>,
    pos: usize,
}

impl<'a> Token<'a> {
    // CONTROL TOKENS
    // --------------------------------------------------------------------------------------------

    pub const USE: &'static str = "use";
    pub const PROC: &'static str = "proc";
    pub const EXPORT: &'static str = "export";

    pub const BEGIN: &'static str = "begin";
    pub const IF: &'static str = "if";
    pub const ELSE: &'static str = "else";
    pub const WHILE: &'static str = "while";
    pub const REPEAT: &'static str = "repeat";
    pub const END: &'static str = "end";

    pub const EXEC: &'static str = "exec";
    pub const CALL: &'static str = "call";
    pub const SYSCALL: &'static str = "syscall";

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new token created from the specified string and position.
    ///
    /// # Panics
    /// Panic is the `token` parameter is an empty string.
    pub fn new(token: &'a str, pos: usize) -> Self {
        assert!(!token.is_empty(), "token cannot be an empty string");
        Self {
            parts: token.split('.').collect(),
            pos,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the position of this token in the source.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Returns the number of parts in this token.
    pub fn num_parts(&self) -> usize {
        self.parts.len()
    }

    /// Returns a reference to this token's parts.
    pub fn parts(&self) -> &[&str] {
        &self.parts
    }

    // STATE MUTATOR
    // --------------------------------------------------------------------------------------------
    /// Updates the contents of this token from the specified string and position.
    ///
    /// # Panics
    /// Panic is the `token` parameter is an empty string.
    pub fn update(&mut self, token: &'a str, pos: usize) {
        assert!(!token.is_empty(), "token cannot be an empty string");
        self.parts.clear();
        token.split('.').for_each(|part| self.parts.push(part));
        self.pos = pos;
    }

    // CONTROL TOKEN PARSERS / VALIDATORS
    // --------------------------------------------------------------------------------------------

    pub fn parse_use(&self) -> Result<AbsolutePath, ParsingError> {
        assert_eq!(Self::USE, self.parts[0], "not a use");
        match self.num_parts() {
            0 => unreachable!(),
            1 => Err(ParsingError::missing_param(self)),
            2 => validate_import_path(self.parts[1], self),
            _ => Err(ParsingError::extra_param(self)),
        }
    }

    pub fn validate_begin(&self) -> Result<(), ParsingError> {
        assert_eq!(Self::BEGIN, self.parts[0], "not a begin");
        if self.num_parts() > 1 {
            Err(ParsingError::extra_param(self))
        } else {
            Ok(())
        }
    }

    pub fn parse_proc(&self) -> Result<(ProcedureName, u16, bool), ParsingError> {
        assert!(
            self.parts[0] == Self::PROC || self.parts[0] == Self::EXPORT,
            "invalid procedure declaration"
        );
        let is_export = self.parts[0] == Self::EXPORT;
        match self.num_parts() {
            0 => unreachable!(),
            1 => Err(ParsingError::missing_param(self)),
            2 => {
                let label = validate_proc_declaration_label(self.parts[1], self)?;
                Ok((label, 0, is_export))
            }
            3 => {
                let label = validate_proc_declaration_label(self.parts[1], self)?;
                let num_locals = validate_proc_locals(self.parts[2], self)?;
                Ok((label, num_locals, is_export))
            }
            _ => Err(ParsingError::extra_param(self)),
        }
    }

    pub fn validate_if(&self) -> Result<(), ParsingError> {
        assert_eq!(Self::IF, self.parts[0], "not an if");
        match self.num_parts() {
            0 => unreachable!(),
            1 => Err(ParsingError::missing_param(self)),
            2 => {
                if self.parts[1] != "true" {
                    Err(ParsingError::invalid_param(self, 1))
                } else {
                    Ok(())
                }
            }
            _ => Err(ParsingError::extra_param(self)),
        }
    }

    pub fn validate_else(&self) -> Result<(), ParsingError> {
        assert_eq!(Self::ELSE, self.parts[0], "not an else");
        if self.num_parts() > 1 {
            Err(ParsingError::extra_param(self))
        } else {
            Ok(())
        }
    }

    pub fn validate_while(&self) -> Result<(), ParsingError> {
        assert_eq!(Self::WHILE, self.parts[0], "not a while");
        match self.num_parts() {
            0 => unreachable!(),
            1 => Err(ParsingError::missing_param(self)),
            2 => {
                if self.parts[1] != "true" {
                    Err(ParsingError::invalid_param(self, 1))
                } else {
                    Ok(())
                }
            }
            _ => Err(ParsingError::extra_param(self)),
        }
    }

    pub fn parse_repeat(&self) -> Result<u32, ParsingError> {
        assert_eq!(Self::REPEAT, self.parts[0], "not a repeat");
        match self.num_parts() {
            0 => unreachable!(),
            1 => Err(ParsingError::missing_param(self)),
            2 => self.parts[1]
                .parse::<u32>()
                .map_err(|_| ParsingError::invalid_param(self, 1)),
            _ => Err(ParsingError::extra_param(self)),
        }
    }

    pub fn parse_exec(&self) -> Result<(&str, Option<&str>), ParsingError> {
        assert_eq!(Self::EXEC, self.parts[0], "not an exec");
        match self.num_parts() {
            0 => unreachable!(),
            1 => Err(ParsingError::missing_param(self)),
            2 => validate_proc_invocation_label(self.parts[1], self),
            _ => Err(ParsingError::extra_param(self)),
        }
    }

    pub fn parse_call(&self) -> Result<(&str, Option<&str>), ParsingError> {
        assert_eq!(Self::CALL, self.parts[0], "not a call");
        match self.num_parts() {
            0 => unreachable!(),
            1 => Err(ParsingError::missing_param(self)),
            2 => validate_proc_invocation_label(self.parts[1], self),
            _ => Err(ParsingError::extra_param(self)),
        }
    }

    pub fn parse_syscall(&self) -> Result<&str, ParsingError> {
        assert_eq!(Self::SYSCALL, self.parts[0], "not a syscall");
        match self.num_parts() {
            0 => unreachable!(),
            1 => Err(ParsingError::missing_param(self)),
            2 => {
                let (proc_name, module_name) = validate_proc_invocation_label(self.parts[1], self)?;
                if module_name.is_some() {
                    return Err(ParsingError::syscall_with_module_name(self));
                }
                Ok(proc_name)
            }
            _ => Err(ParsingError::extra_param(self)),
        }
    }

    pub fn validate_end(&self) -> Result<(), ParsingError> {
        assert_eq!(Self::END, self.parts[0], "not an end");
        if self.num_parts() > 1 {
            Err(ParsingError::extra_param(self))
        } else {
            Ok(())
        }
    }
}

impl<'a> fmt::Display for Token<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.parts.join("."))
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns a procedure name instantiated from the provided procedure declaration label.
///
/// Label of a declared procedure must comply with the following rules:
/// - It must start with an ascii letter.
/// - It can contain only ascii letters, numbers, or underscores.
fn validate_proc_declaration_label(
    label: &str,
    token: &Token,
) -> Result<ProcedureName, ParsingError> {
    if !is_valid_label(label) {
        return Err(ParsingError::invalid_proc_name(token, label));
    }

    if label.len() > MAX_PROC_NAME_LEN as usize {
        return Err(ParsingError::proc_name_too_long(
            token,
            label,
            MAX_PROC_NAME_LEN,
        ));
    }

    ProcedureName::try_from(label.to_string())
        .map_err(|e| ParsingError::invalid_library_path(token, e))
}

/// A label of an invoked procedure must comply with the following rules:
/// - It must start with an ascii letter.
/// - It can contain only ascii letters, numbers, underscores, or colons.
///
/// As compared to procedure declaration label, colons are allowed here to support invocation
/// of imported procedures.
fn validate_proc_invocation_label<'a>(
    label: &'a str,
    token: &'a Token,
) -> Result<(&'a str, Option<&'a str>), ParsingError> {
    // a label must start with a letter
    if label.is_empty() || !label.chars().next().unwrap().is_ascii_alphabetic() {
        return Err(ParsingError::invalid_proc_invocation(token, label));
    }

    let mut parts = label.split(MODULE_PATH_DELIM);
    let (proc_name, module_name) = match (parts.next(), parts.next()) {
        (None, _) => return Err(ParsingError::invalid_proc_invocation(token, label)),
        (Some(proc_name), None) => {
            if !is_valid_label(proc_name) {
                return Err(ParsingError::invalid_proc_invocation(token, label));
            }
            (proc_name, None)
        }
        (Some(module_name), Some(proc_name)) => {
            if !is_valid_label(proc_name) || !is_valid_label(module_name) || parts.next().is_some()
            {
                return Err(ParsingError::invalid_proc_invocation(token, label));
            }
            (proc_name, Some(module_name))
        }
    };

    Ok((proc_name, module_name))
}

/// Procedure locals must be a 16-bit integer.
fn validate_proc_locals(locals: &str, token: &Token) -> Result<u16, ParsingError> {
    match locals.parse::<u64>() {
        Ok(num_locals) => {
            if num_locals > u16::MAX as u64 {
                return Err(ParsingError::too_many_proc_locals(
                    token,
                    num_locals,
                    u16::MAX as u64,
                ));
            }
            Ok(num_locals as u16)
        }
        Err(_) => Err(ParsingError::invalid_proc_locals(token, locals)),
    }
}

/// A module import path must comply with the following rules:
/// - It must start with an ascii letter.
/// - It can contain only ascii letters, numbers, underscores, or colons.
fn validate_import_path(path: &str, token: &Token) -> Result<AbsolutePath, ParsingError> {
    // a path must start with a letter
    if path.is_empty() || !path.chars().next().unwrap().is_ascii_alphabetic() {
        return Err(ParsingError::invalid_module_path(token, path));
    }

    // a path can contain only letters, numbers, underscores, or colons
    if !path
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
    {
        return Err(ParsingError::invalid_module_path(token, path));
    }

    Ok(AbsolutePath::new_unchecked(path.to_string()))
}

/// Returns true if the provided label is valid and false otherwise.
///
/// A label is considered valid if it start with a letter and consists only of letters, numbers,
/// and underscores.
fn is_valid_label(label: &str) -> bool {
    // a label must start with a letter
    if label.is_empty() || !label.chars().next().unwrap().is_ascii_alphabetic() {
        return false;
    }

    // a label can contain only letters, numbers, or underscores
    if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }

    true
}
