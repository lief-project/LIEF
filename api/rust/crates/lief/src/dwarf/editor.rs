use lief_ffi as ffi;

use crate::{common::FromFFI, common::into_optional, enum_from_int, generic};
use std::marker::PhantomData;
use std::option::Option;
use std::path::Path;

pub mod compilation_unit;
pub mod function;
pub mod types;
pub mod variable;

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

enum_from_int! {
    #[allow(non_camel_case_types)]
    Format: u32 {
        ELF = 0x00000000,
        MACHO = 0x00000001,
        PE = 0x00000002,
    }
}
enum_from_int! {
    #[allow(non_camel_case_types)]
    Arch: u32 {
        X64 = 0x00000001,
        X86 = 0x00000002,
        AARCH64 = 0x00000003,
        ARM = 0x00000004,
    }
}
impl<'a> Editor<'a> {
    /// Instantiate an editor for the given binary object
    pub fn from_binary(bin: &'a mut dyn generic::Binary) -> Option<Editor<'a>> {
        into_optional(ffi::DWARF_Editor::from_binary(bin.as_pin_mut_generic()))
    }

    /// Instantiate an editor for the given format and arch
    pub fn create(fmt: Format, arch: Arch) -> Option<Editor<'static>> {
        into_optional(ffi::DWARF_Editor::create(fmt.into(), arch.into()))
    }

    /// Create a new compilation unit
    pub fn create_compile_unit(&mut self) -> Option<CompilationUnit<'_>> {
        into_optional(self.ptr.pin_mut().create_compilation_unit())
    }

    /// Write the DWARF file to the specified output
    pub fn write<P: AsRef<Path>>(&mut self, output: P) {
        cxx::let_cxx_string!(__cxx_s = output.as_ref().to_str().unwrap());
        self.ptr.pin_mut().write(&__cxx_s)
    }
}
