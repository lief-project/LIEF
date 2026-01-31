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

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Format {
    ELF,
    MACHO,
    PE,
    UNKNOWN(u32),
}

impl From<u32> for Format {
    fn from(value: u32) -> Self {
        match value {
            0x00000000 => Format::ELF,
            0x00000001 => Format::MACHO,
            0x00000002 => Format::PE,
            _ => Format::UNKNOWN(value),

        }
    }
}
impl From<Format> for u32 {
    fn from(value: Format) -> u32 {
        match value {
            Format::ELF => 0x00000000,
            Format::MACHO => 0x00000001,
            Format::PE => 0x00000002,
            Format::UNKNOWN(_) => 0,

        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Arch {
    X64,
    X86,
    AARCH64,
    ARM,
    UNKNOWN(u32),
}

impl From<u32> for Arch {
    fn from(value: u32) -> Self {
        match value {
            0x00000000 => Arch::X64,
            0x00000001 => Arch::X86,
            0x00000002 => Arch::AARCH64,
            0x00000003 => Arch::ARM,
            _ => Arch::UNKNOWN(value),

        }
    }
}
impl From<Arch> for u32 {
    fn from(value: Arch) -> u32 {
        match value {
            Arch::X64 => 0x00000000,
            Arch::X86 => 0x00000001,
            Arch::AARCH64 => 0x00000002,
            Arch::ARM => 0x00000003,
            Arch::UNKNOWN(_) => 0,

        }
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
        self.ptr.pin_mut().write(output.as_ref().to_str().unwrap())
    }
}

