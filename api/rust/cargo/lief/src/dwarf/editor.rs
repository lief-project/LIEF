use lief_ffi as ffi;

use std::path::Path;
use std::option::Option;
use std::marker::PhantomData;
use crate::{common::FromFFI, generic, common::into_optional};

pub mod compilation_unit;
pub mod function;
pub mod variable;
pub mod types;

#[doc(inline)]
pub use compilation_unit::CompilationUnit;

#[doc(inline)]
pub use types::Type;

#[doc(inline)]
pub use variable::Variable;

#[doc(inline)]
pub use function::Function;

/// This structure exposes the main API to create DWARF information
pub struct Editor<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_Editor>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_Editor> for Editor<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_Editor>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl<'a> Editor<'a> {
    /// Instantiate an editor for the given binary object
    pub fn from_binary(bin: &'a mut dyn generic::Binary) -> Option<Editor<'a>> {
        into_optional(ffi::DWARF_Editor::from_binary(bin.as_pin_mut_generic()))
    }

    /// Create a new compilation unit
    pub fn create_compile_unit(&mut self) -> Option<CompilationUnit> {
        into_optional(self.ptr.pin_mut().create_compilation_unit())
    }

    /// Write the DWARF file to the specified output
    pub fn write<P: AsRef<Path>>(&mut self, output: P) {
        self.ptr.pin_mut().write(output.as_ref().to_str().unwrap())
    }
}

