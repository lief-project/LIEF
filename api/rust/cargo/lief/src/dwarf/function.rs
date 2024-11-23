use lief_ffi as ffi;

use super::variable::Variables;
use super::{Scope, Type, Parameters};
use crate::common::{into_optional, into_ranges, FromFFI};
use crate::declare_fwd_iterator;
use crate::to_result;
use crate::DebugLocation;
use crate::Error;
use crate::Range;
use crate::assembly;
use std::marker::PhantomData;

/// This structure represents a DWARF function which can be associated with either:
/// `DW_TAG_subprogram` or `DW_TAG_inlined_subroutine`.
pub struct Function<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_Function>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_Function> for Function<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_Function>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl Function<'_> {
    /// The name of the function (`DW_AT_name`)
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// The name of the function which is used for linking (`DW_AT_linkage_name`).
    ///
    /// This name differs from [`Function::name`] as it is usually mangled. The function
    /// return an empty string if the linkage name is not available.
    pub fn linkage_name(&self) -> String {
        self.ptr.linkage_name().to_string()
    }

    /// Return the address of the function (`DW_AT_entry_pc` or `DW_AT_low_pc`).
    pub fn address(&self) -> Result<u64, Error> {
        to_result!(ffi::DWARF_Function::address, self);
    }

    /// Return an iterator of variables (`DW_TAG_variable`) defined within the
    /// scope of this function. This includes regular stack-based variables as
    /// well as static ones.
    pub fn variables(&self) -> Variables {
        Variables::new(self.ptr.variables())
    }

    /// Whether this function is created by the compiler and not
    /// present in the original source code
    pub fn is_artificial(&self) -> bool {
        self.ptr.is_artificial()
    }

    /// Whether the function is defined **outside** the compilation unit (`DW_AT_external`)
    pub fn is_external(&self) -> bool {
        self.ptr.is_external()
    }

    /// Return the size taken by this function in the binary
    pub fn size(&self) -> u64 {
        self.ptr.size()
    }

    /// Ranges of virtual addresses owned by this function
    pub fn ranges(&self) -> Vec<Range> {
        into_ranges(self.ptr.ranges())
    }

    /// Original source code location
    pub fn debug_location(&self) -> DebugLocation {
        DebugLocation::from_ffi(self.ptr.debug_location())
    }

    /// Return the [`Type`] associated with the **return type** of this function.
    pub fn return_type(&self) -> Option<Type> {
        into_optional(self.ptr.get_type())
    }

    /// Return an iterator over the [`Parameters`] of this function
    pub fn parameters(&self) -> ParametersIt {
        ParametersIt::new(self.ptr.parameters())
    }

    /// List of exceptions (types) that can be thrown by the function.
    ///
    /// For instance, given this Swift code:
    ///
    /// ```swift
    /// func summarize(_ ratings: [Int]) throws(StatisticsError) {
    ///   // ...
    /// }
    /// ```
    ///
    /// [`Function::thrown_types`] returns one element associated with the [`Type`]:
    /// `StatisticsError`.
    pub fn thrown_types(&self) -> ThrownTypes {
        ThrownTypes::new(self.ptr.thrown_types())
    }

    /// The scope in which this function is defined
    pub fn scope(&self) -> Option<Scope> {
        into_optional(self.ptr.scope())
    }

    /// Disassemble the current function by returning an iterator over
    /// the [`assembly::Instructions`]
    pub fn instructions(&self) -> Instructions {
        Instructions::new(self.ptr.instructions())
    }
}

declare_fwd_iterator!(
    Functions,
    Function<'a>,
    ffi::DWARF_Function,
    ffi::DWARF_CompilationUnit,
    ffi::DWARF_CompilationUnit_it_functions
);

declare_fwd_iterator!(
    ParametersIt,
    Parameters<'a>,
    ffi::DWARF_Parameter,
    ffi::DWARF_Function,
    ffi::DWARF_Function_it_parameters
);

declare_fwd_iterator!(
    ThrownTypes,
    Type<'a>,
    ffi::DWARF_Type,
    ffi::DWARF_Function,
    ffi::DWARF_Function_it_thrown_types
);


declare_fwd_iterator!(
    Instructions,
    assembly::Instructions,
    ffi::asm_Instruction,
    ffi::DWARF_Function,
    ffi::DWARF_Function_it_instructions
);
