use lief_ffi as ffi;

use std::marker::PhantomData;
use crate::common::{into_optional, FromFFI};
use crate::generic;
use crate::dwarf::function::Function;
use crate::dwarf::variable::Variable;
use crate::dwarf::types::Type;

use super::compilation_unit::CompilationUnits;

/// This class represents a DWARF debug information. It can embed different
/// compilation units which can be accessed through compilation_units() .
///
/// This class can be instantiated from [`crate::generic::Binary::debug_info`] or using the
/// function [`crate::dwarf::load`]
pub struct DebugInfo<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_DebugInfo>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_DebugInfo> for DebugInfo<'_> {
    fn from_ffi(info: cxx::UniquePtr<ffi::DWARF_DebugInfo>) -> Self {
        Self {
            ptr: info,
            _owner: PhantomData
        }
    }
}

impl DebugInfo<'_> {
    /// Iterator on the [`crate::dwarf::CompilationUnit`] embedded in this dwarf
    pub fn compilation_units(&self) -> CompilationUnits {
        CompilationUnits::new(self.ptr.compilation_units())
    }

    /// Try to find the function with the given name (mangled or not)
    ///
    /// ```
    /// if let Some(func) = info.function_by_name("_ZNSt6localeD1Ev") {
    ///     // Found
    /// }
    /// if let Some(func) = info.function_by_name("std::locale::~locale()") {
    ///     // Found
    /// }
    /// ```
    pub fn function_by_name(&self, name: &str) -> Option<Function> {
        into_optional(self.ptr.function_by_name(name))
    }

    /// Try to find the function at the given **virtual** address
    pub fn function_by_addr(&self, addr: u64) -> Option<Function> {
        into_optional(self.ptr.function_by_addr(addr))
    }

    /// Try to find the variable with the given name. This name can be mangled or
    /// not.
    pub fn variable_by_name(&self, name: &str) -> Option<Variable> {
        into_optional(self.ptr.variable_by_name(name))
    }

    /// Try to find the (static) variable at the given **virtual** address
    pub fn variable_by_addr(&self, addr: u64) -> Option<Variable> {
        into_optional(self.ptr.variable_by_addr(addr))
    }

    /// Try to find the (static) variable at the given **virtual** address
    pub fn type_by_name(&self, name: &str) -> Option<Type> {
        into_optional(self.ptr.type_by_name(name))
    }
}

impl generic::DebugInfo for DebugInfo<'_> {
    fn as_generic(&self) -> &ffi::AbstracDebugInfo {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
