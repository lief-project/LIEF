use lief_ffi as ffi;

use super::Type;
use crate::common::into_optional;
use crate::common::FromFFI;
use crate::DebugLocation;
use crate::{declare_fwd_iterator, to_result, Error};
use std::marker::PhantomData;
use crate::dwarf::Scope;

/// Return an iterator of the variable `DW_TAG_variable` defined within the
/// scope of this function. This includes regular stack-based variables as
/// well as static ones.
pub struct Variable<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_Variable>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_Variable> for Variable<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_Variable>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl Variable<'_> {
    /// Name of the variable (usually demangled)
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// The name of the variable which is used for linking (`DW_AT_linkage_name`).
    ///
    /// This name differs from [`Variable::name`] as it is usually mangled.
    pub fn linkage_name(&self) -> Option<String> {
        let name = self.ptr.name().to_string();
        if !name.is_empty() {
            return Some(name);
        }
        None
    }

    /// Address of the variable.
    ///
    /// If the variable is **static**, it returns the **virtual address**
    /// where it is defined.
    /// If the variable is stack-based, it returns the **relative offset** from
    /// the frame based register.
    ///
    /// If the address can't be resolved, it returns an [`Error`].
    pub fn address(&self) -> Result<i64, Error> {
        to_result!(ffi::DWARF_Variable::address, self);
    }

    /// Return the size of the variable (or an [`Error`] if it can't be
    /// resolved).
    ///
    /// This size is defined by its type.
    pub fn size(&self) -> Result<u64, Error> {
        to_result!(ffi::DWARF_Variable::size, self);
    }

    /// Whether it's a `constexpr` variable
    pub fn is_constexpr(&self) -> bool {
        self.ptr.is_constexpr()
    }

    /// The original source location where the variable is defined.
    pub fn debug_location(&self) -> DebugLocation {
        DebugLocation::from_ffi(self.ptr.debug_location())
    }

    /// Return the type of this variable
    pub fn get_type(&self) -> Option<Type> {
        into_optional(self.ptr.get_type())
    }

    /// The scope in which this variable is defined
    pub fn scope(&self) -> Option<Scope> {
        into_optional(self.ptr.scope())
    }
}

declare_fwd_iterator!(
    Variables,
    Variable<'a>,
    ffi::DWARF_Variable,
    ffi::DWARF_Function,
    ffi::DWARF_Function_it_variables
);

declare_fwd_iterator!(
    CompilationUnitVariables,
    Variable<'a>,
    ffi::DWARF_Variable,
    ffi::DWARF_CompilationUnit,
    ffi::DWARF_CompilationUnit_it_variables
);
