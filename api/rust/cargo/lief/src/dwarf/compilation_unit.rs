//! This module wraps DWARF compilation unit

use lief_ffi as ffi;

use std::marker::PhantomData;

use crate::common::{into_optional, into_ranges, FromFFI};
use crate::declare_fwd_iterator;
use crate::Range;

use super::{Function, Variable};
use crate::dwarf::variable::CompilationUnitVariables;
use crate::dwarf::function::Functions;
use crate::dwarf::types::Types;

/// A DWARF compilation unit
pub struct CompilationUnit<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_CompilationUnit>,
    _owner: PhantomData<&'a ()>,
}


#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Langs {
    C,
    CPP,
    RUST,
    DART,
    UNKNOWN(u32),
}

impl From<u32> for Langs {
    fn from(value: u32) -> Self {
        match value {
            0x00000001 => Langs::C,
            0x00000002 => Langs::CPP,
            0x00000003 => Langs::RUST,
            0x00000004 => Langs::DART,
            _ => Langs::UNKNOWN(value),

        }
    }
}
impl From<Langs> for u32 {
    fn from(value: Langs) -> u32 {
        match value {
            Langs::C => 0x00000001,
            Langs::CPP => 0x00000002,
            Langs::RUST => 0x00000003,
            Langs::DART => 0x00000004,
            Langs::UNKNOWN(_) => 0,
        }
    }
}

/// Languages supported by the DWARF (v5) format.
/// See: <https://dwarfstd.org/languages.html>
///
/// Some languages (like C++11, C++17, ..) have a version (11, 17, ...) which
/// is stored in a dedicated attribute: #version
#[derive(Debug)]
pub struct Language {
    /// The language itself
    pub lang: Langs,

    /// Version of the language (e.g. 17 for C++17)
    pub version: u32,
}

impl FromFFI<ffi::DWARF_CompilationUnit_Language> for Language {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_CompilationUnit_Language>) -> Self {
        let lang_ref = ptr.as_ref().unwrap();
        Self {
            lang: Langs::from(lang_ref.lang),
            version: lang_ref.version,
        }
    }
}

impl FromFFI<ffi::DWARF_CompilationUnit> for CompilationUnit<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_CompilationUnit>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl CompilationUnit<'_> {
    /// Name of the file associated with this compilation unit (e.g. `test.cpp`)
    /// Return an **empty** string if the name is not found or can't be resolved
    ///
    /// This value matches the `DW_AT_name` attribute
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// Information about the program (or library) that generated this compilation
    /// unit. For instance, it can output: `Debian clang version 17.0.6`.
    ///
    /// It returns an **empty** string if the producer is not present or can't be
    /// resolved
    ///
    /// This value matches the `DW_AT_producer` attribute
    pub fn producer(&self) -> String {
        self.ptr.producer().to_string()
    }

    /// Return the path to the directory in which the compilation took place for
    /// compiling this compilation unit (e.g. `/workdir/build`)
    ///
    /// It returns an **empty** string if the entry is not present or can't be
    /// resolved
    ///
    /// This value matches the `DW_AT_comp_dir` attributeducer` attribute
    pub fn compilation_dir(&self) -> String {
        self.ptr.compilation_dir().to_string()
    }

    /// Original Language of this compilation unit.
    ///
    /// This value matches the `DW_AT_language` attribute
    pub fn language(&self) -> Language {
        Language::from_ffi(self.ptr.language())
    }

    /// Return the lowest virtual address owned by this compilation unit.
    pub fn low_address(&self) -> u64 {
        self.ptr.low_address()
    }

    /// Return the highest virtual address owned by this compilation unit.
    pub fn high_address(&self) -> u64 {
        self.ptr.high_address()
    }

    /// Return the size of the compilation unit according to its range of address.
    ///
    /// If the compilation is fragmented (i.e. there are some address ranges
    /// between the lowest address and the highest that are not owned by the CU),
    /// then it returns the sum of **all** the address ranges owned by this CU.
    ///
    /// If the compilation unit is **not** fragmented, then is basically returns
    /// `high_address - low_address`.
    pub fn size(&self) -> u64 {
        self.ptr.size()
    }

    /// Return a list of address ranges owned by this compilation unit.
    ///
    /// If the compilation unit owns a contiguous range, it should return
    /// **a single** range.
    pub fn ranges(&self) -> Vec<Range> {
        into_ranges(self.ptr.ranges())
    }

    /// Return an iterator over the functions [`Function`] implemented in this compilation
    /// unit.
    ///
    /// Note that this iterator only iterates over the functions that have a
    /// **concrete** implementation in the compilation unit.
    ///
    /// For instance with this code:
    ///
    /// ```cpp
    /// inline const char* get_secret_env() {
    ///   return getenv("MY_SECRET_ENV");
    /// }
    ///
    /// int main() {
    ///   printf("%s", get_secret_env());
    ///   return 0;
    /// }
    /// ```
    ///
    /// The iterator will only return **one function** for `main` since
    /// `get_secret_env` is inlined and thus, its implementation is located in
    /// `main`.
    pub fn functions(&self) -> Functions {
        Functions::new(self.ptr.functions())
    }

    /// Return an iterator over the variables defined in the **global** scope
    /// of this compilation unit:
    ///
    /// ```cpp
    /// static int A = 1; // Returned by the iterator
    /// static const char* B = "Hello"; // Returned by the iterator
    ///
    /// int get() {
    ///   static int C = 2; // Returned by the iterator
    ///   return C;
    /// }
    /// ```
    pub fn variables(&self) -> CompilationUnitVariables {
        CompilationUnitVariables::new(self.ptr.variables())
    }

    pub fn types(&self) -> Types {
        Types::new(self.ptr.types())
    }

    /// Try to find the function whose name is given in parameter.
    ///
    /// The provided name can be demangled.
    pub fn function_by_name(&self, name: &str) -> Option<Function> {
        into_optional(self.ptr.function_by_name(name))
    }

    /// Try to find the function at the given address
    pub fn function_by_addr(&self, address: u64) -> Option<Function> {
        into_optional(self.ptr.function_by_address(address))
    }

    /// Try to find the variable whose name is given in parameter.
    pub fn variable_by_name(&self, name: &str) -> Option<Variable> {
        into_optional(self.ptr.variable_by_name(name))
    }

    /// Try to find the variable at the given address
    pub fn variable_by_addr(&self, address: u64) -> Option<Variable> {
        into_optional(self.ptr.variable_by_address(address))
    }
}

declare_fwd_iterator!(
    CompilationUnits,
    CompilationUnit<'a>,
    ffi::DWARF_CompilationUnit,
    ffi::DWARF_DebugInfo,
    ffi::DWARF_DebugInfo_it_compilation_units
);
