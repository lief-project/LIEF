use std::marker::PhantomData;

use crate::common::{into_optional, FromFFI};
use crate::declare_iterator;
use crate::generic;
use lief_ffi as ffi;

use super::commands::Dylib;
use super::{BindingInfo, ExportInfo};

pub struct Symbol<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_Symbol>,
    _owner: PhantomData<&'a ()>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum CATEGORY {
    NONE,
    LOCAL,
    EXTERNAL,
    UNDEFINED,
    INDIRECT_ABS,
    INDIRECT_LOCAL,
    UNKNOWN(u32),
}

impl CATEGORY {
    pub fn from_value(value: u32) -> Self {
        match value {
            0x00000000 => CATEGORY::NONE,
            0x00000001 => CATEGORY::LOCAL,
            0x00000002 => CATEGORY::EXTERNAL,
            0x00000003 => CATEGORY::UNDEFINED,
            0x00000004 => CATEGORY::INDIRECT_ABS,
            0x00000005 => CATEGORY::INDIRECT_LOCAL,
            _ => CATEGORY::UNKNOWN(value),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ORIGIN {
    DYLD_EXPORT,
    DYLD_BIND,
    LC_SYMTAB,
    UNKNOWN(u32),
}

impl ORIGIN {
    pub fn from_value(value: u32) -> Self {
        match value {
            0x00000001 => ORIGIN::DYLD_EXPORT,
            0x00000002 => ORIGIN::DYLD_BIND,
            0x00000003 => ORIGIN::LC_SYMTAB,
            _ => ORIGIN::UNKNOWN(value),
        }
    }
}

impl Symbol<'_> {
    pub fn get_type(&self) -> u8 {
        self.ptr.get_type()
    }

    pub fn numberof_sections(&self) -> u8 {
        self.ptr.numberof_sections()
    }

    pub fn description(&self) -> u16 {
        self.ptr.description()
    }

    pub fn origin(&self) -> ORIGIN {
        ORIGIN::from_value(self.ptr.origin())
    }

    pub fn category(&self) -> CATEGORY {
        CATEGORY::from_value(self.ptr.category())
    }

    pub fn export_info(&self) -> Option<ExportInfo> {
        into_optional(self.ptr.export_info())
    }

    pub fn binding_info(&self) -> Option<BindingInfo> {
        into_optional(self.ptr.binding_info())
    }

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
