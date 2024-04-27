use lief_ffi as ffi;
use std::fmt;
use std::marker::PhantomData;

use crate::common::{FromFFI, into_optional};
use crate::declare_iterator;
use crate::generic;
use crate::elf::Section;
use super::SymbolVersion;

pub struct Symbol<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_Symbol>,
    _owner: PhantomData<&'a ffi::ELF_Binary>
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Binding {
    LOCAL,
    GLOBAL,
    WEAK,
    GNU_UNIQUE,
    UNKNOWN(u32),
}

impl Binding {
    pub fn from_value(value: u32) -> Self {
        match value {
            0x00000000 => Binding::LOCAL,
            0x00000001 => Binding::GLOBAL,
            0x00000002 => Binding::WEAK,
            0x0000000a => Binding::GNU_UNIQUE,
            _ => Binding::UNKNOWN(value),

        }
    }
}


#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Type {
    NOTYPE,
    OBJECT,
    FUNC,
    SECTION,
    FILE,
    COMMON,
    TLS,
    GNU_IFUNC,
    UNKNOWN(u32),
}

impl Type {
    pub fn from_value(value: u32) -> Self {
        match value {
            0x00000000 => Type::NOTYPE,
            0x00000001 => Type::OBJECT,
            0x00000002 => Type::FUNC,
            0x00000003 => Type::SECTION,
            0x00000004 => Type::FILE,
            0x00000005 => Type::COMMON,
            0x00000006 => Type::TLS,
            0x0000000a => Type::GNU_IFUNC,
            _ => Type::UNKNOWN(value),

        }
    }
}


#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Visibility {
    DEFAULT,
    INTERNAL,
    HIDDEN,
    PROTECTED,
    UNKNOWN(u32),
}

impl Visibility {
    pub fn from_value(value: u32) -> Self {
        match value {
            0x00000000 => Visibility::DEFAULT,
            0x00000001 => Visibility::INTERNAL,
            0x00000002 => Visibility::HIDDEN,
            0x00000003 => Visibility::PROTECTED,
            _ => Visibility::UNKNOWN(value),

        }
    }
}

impl Symbol<'_> {
    pub fn get_type(&self) -> Type {
        Type::from_value(self.ptr.get_type())
    }
    pub fn binding(&self) -> Binding {
        Binding::from_value(self.ptr.binding())
    }
    pub fn information(&self) -> u8 {
        self.ptr.information()
    }
    pub fn other(&self) -> u8 {
        self.ptr.other()
    }
    pub fn section_idx(&self) -> u16 {
        self.ptr.section_idx()
    }
    pub fn visibility(&self) -> Visibility {
        Visibility::from_value(self.ptr.visibility())
    }
    pub fn section(&self) -> Option<Section> {
        into_optional(self.ptr.section())
    }
    pub fn symbol_version(&self) -> Option<SymbolVersion> {
        into_optional(self.ptr.symbol_version())
    }
}

impl fmt::Debug for Symbol<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
       let base = self as &dyn generic::Symbol;
        f.debug_struct("Symbol")
            .field("base", &base)
            .field("type", &self.get_type())
            .field("binding", &self.binding())
            .field("information", &self.information())
            .field("other", &self.other())
            .field("section_idx", &self.section_idx())
            .field("visibility", &self.visibility())
            .field("section", &self.section())
            .field("symbol_version", &self.symbol_version())
            .finish()
    }
}

impl FromFFI<ffi::ELF_Symbol> for Symbol<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_Symbol>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

impl generic::Symbol for Symbol<'_> {
    fn as_generic(&self) -> &ffi::AbstractSymbol {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl fmt::Display for Symbol<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}

declare_iterator!(DynamicSymbols, Symbol<'a>, ffi::ELF_Symbol, ffi::ELF_Binary, ffi::ELF_Binary_it_dynamic_symbols);
declare_iterator!(ExportedSymbols, Symbol<'a>, ffi::ELF_Symbol, ffi::ELF_Binary, ffi::ELF_Binary_it_exported_symbols);
declare_iterator!(ImportedSymbols, Symbol<'a>, ffi::ELF_Symbol, ffi::ELF_Binary, ffi::ELF_Binary_it_imported_symbols);
declare_iterator!(SymtabSymbols, Symbol<'a>, ffi::ELF_Symbol, ffi::ELF_Binary, ffi::ELF_Binary_it_symtab_symbols);
