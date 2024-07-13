//! This module wraps a PDB compilation unit

use lief_ffi as ffi;

use std::marker::PhantomData;

use crate::common::FromFFI;
use crate::declare_fwd_iterator;

use super::function::Functions;

/// This structure represents a CompilationUnit (or Module) in a PDB file
pub struct CompilationUnit<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_CompilationUnit>,
    _owner: PhantomData<&'a ()>,
}


impl FromFFI<ffi::PDB_CompilationUnit> for CompilationUnit<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PDB_CompilationUnit>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl CompilationUnit<'_> {
    /// Name (or path) to the COFF object (`.obj`) associated with this
    /// compilation unit (e.g. `e:\obj.amd64fre\minkernel\ntos\hvl\mp\objfre\amd64\hvlp.obj`)
    pub fn module_name(&self) -> String {
        self.ptr.module_name().to_string()
    }

    /// Name of path to the original binary object (COFF, Archive) in which
    /// the compilation unit was located before being linked.
    /// e.g. `e:\obj.amd64fre\minkernel\ntos\hvl\mp\objfre\amd64\hvl.lib`
    pub fn object_filename(&self) -> String {
        self.ptr.object_filename().to_string()
    }

    /// Return an iterator over the [`crate::pdb::Function`] defined in this compilation unit.
    /// If the PDB does not contain or has an empty DBI stream, it returns
    /// an empty iterator.
    pub fn functions(&self) -> Functions {
        Functions::new(self.ptr.functions())
    }

    /// Iterator over the sources files (as string) that compose this compilation unit.
    /// These files include the **header** (`.h, .hpp`, ...).
    pub fn sources(&self) -> Sources {
        Sources::new(self.ptr.sources())
    }
}

declare_fwd_iterator!(
    CompilationUnits,
    CompilationUnit<'a>,
    ffi::PDB_CompilationUnit,
    ffi::PDB_DebugInfo,
    ffi::PDB_DebugInfo_it_compilation_units
);


pub struct Sources<'a> {
    #[doc(hidden)]
    pub it: cxx::UniquePtr<ffi::PDB_CompilationUnit_it_sources>,
    _owner: PhantomData<&'a ffi::PDB_CompilationUnit>,
}

impl Sources<'_> {
    #[doc(hidden)]
    pub fn new(it: cxx::UniquePtr<ffi::PDB_CompilationUnit_it_sources>) -> Self {
        Self {
            it,
            _owner: PhantomData,
        }
    }
}

impl Iterator for Sources<'_> {
    type Item = String;
    fn next(&mut self) -> Option<Self::Item> {
        let string = self.it.as_mut().unwrap().next().to_string();
        // c.f. comment in rust/LIEF/PDB/CompilationUnit.hpp
        if string == "[LIEF_STOP]" {
            None
        } else {
            Some(string)
        }
    }
}
