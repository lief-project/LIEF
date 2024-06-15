use std::marker::PhantomData;

use crate::common::{into_optional, FromFFI};
use crate::declare_iterator;
use crate::generic;
use lief_ffi as ffi;

use super::commands::Dylib;
use super::{BindingInfo, ExportInfo};

/// Structure that represents a Symbol in a Mach-O file.
///
/// A Mach-O symbol can come from:
/// 1. The symbols command (LC_SYMTAB / SymbolCommand)
/// 2. The Dyld Export trie
/// 3. The Dyld Symbol bindings
pub struct Symbol<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_Symbol>,
    _owner: PhantomData<&'a ()>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Category {
    NONE,
    LOCAL,
    EXTERNAL,
    UNDEFINED,
    INDIRECT_ABS,
    INDIRECT_LOCAL,
    UNKNOWN(u32),
}

impl From<u32> for Category {
    fn from(value: u32) -> Self {
        match value {
            0x00000000 => Category::NONE,
            0x00000001 => Category::LOCAL,
            0x00000002 => Category::EXTERNAL,
            0x00000003 => Category::UNDEFINED,
            0x00000004 => Category::INDIRECT_ABS,
            0x00000005 => Category::INDIRECT_LOCAL,
            _ => Category::UNKNOWN(value),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Origin {
    DYLD_EXPORT,
    DYLD_BIND,
    LC_SYMTAB,
    UNKNOWN(u32),
}

impl From<u32> for Origin {
    fn from(value: u32) -> Self {
        match value {
            0x00000001 => Origin::DYLD_EXPORT,
            0x00000002 => Origin::DYLD_BIND,
            0x00000003 => Origin::LC_SYMTAB,
            _ => Origin::UNKNOWN(value),
        }
    }
}

impl Symbol<'_> {
    pub fn get_type(&self) -> u8 {
        self.ptr.get_type()
    }

    /// It returns the number of sections in which this symbol can be found.
    /// If the symbol can't be found in any section, it returns 0 (`NO_SECT`)
    pub fn numberof_sections(&self) -> u8 {
        self.ptr.numberof_sections()
    }

    /// Return information about the symbol
    pub fn description(&self) -> u16 {
        self.ptr.description()
    }

    /// Return the origin of the symbol: from `LC_SYMTAB` from the Dyld information, ...
    pub fn origin(&self) -> Origin {
        Origin::from(self.ptr.origin())
    }

    /// Category of the symbol according to the `LC_DYSYMTAB` command
    pub fn category(&self) -> Category {
        Category::from(self.ptr.category())
    }

    /// Export info associated with this symbol (if any)
    pub fn export_info(&self) -> Option<ExportInfo> {
        into_optional(self.ptr.export_info())
    }

    /// Binding info associated with this symbol (if any)
    pub fn binding_info(&self) -> Option<BindingInfo> {
        into_optional(self.ptr.binding_info())
    }

    /// Return the library in which this symbol is defined (if any)
    pub fn library(&self) -> Option<Dylib> {
        into_optional(self.ptr.library())
    }
}

impl std::fmt::Debug for Symbol<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn generic::Symbol;
        f.debug_struct("Symbol")
            .field("base", &base)
            .field("type", &self.get_type())
            .field("numberof_sections", &self.numberof_sections())
            .field("description", &self.description())
            .field("origin", &self.origin())
            .field("category", &self.category())
            .field("export_info", &self.export_info())
            .field("binding_info", &self.binding_info())
            .field("library", &self.library())
            .finish()
    }
}

impl<'a> FromFFI<ffi::MachO_Symbol> for Symbol<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::MachO_Symbol>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl generic::Symbol for Symbol<'_> {
    fn as_generic(&self) -> &ffi::AbstractSymbol {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

declare_iterator!(
    Symbols,
    Symbol<'a>,
    ffi::MachO_Symbol,
    ffi::MachO_Binary,
    ffi::MachO_Binary_it_symbols
);
