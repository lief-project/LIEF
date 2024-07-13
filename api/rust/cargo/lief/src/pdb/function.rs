use lief_ffi as ffi;

use std::marker::PhantomData;

use crate::DebugLocation;
use crate::common::FromFFI;
use crate::declare_fwd_iterator;

pub struct Function<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_Function>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::PDB_Function> for Function<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PDB_Function>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl Function<'_> {
    /// The name of the function (this name is usually demangled)
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// The **Relative** Virtual Address of the function
    pub fn rva(&self) -> u32 {
        self.ptr.RVA()
    }

    /// The size of the function
    pub fn code_size(&self) -> u32 {
        self.ptr.code_size()
    }

    /// The name of the section in which this function is defined
    pub fn section_name(&self) -> String {
        self.ptr.section_name().to_string()
    }

    /// Original source code location
    pub fn debug_location(&self) -> DebugLocation {
        DebugLocation::from_ffi(self.ptr.debug_location())
    }
}

declare_fwd_iterator!(
    Functions,
    Function<'a>,
    ffi::PDB_Function,
    ffi::PDB_CompilationUnit,
    ffi::PDB_CompilationUnit_it_functions
);
