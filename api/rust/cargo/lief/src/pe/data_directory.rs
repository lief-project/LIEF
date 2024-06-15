//! PE Data Directory module

use std::marker::PhantomData;

use crate::common::into_optional;
use crate::common::FromFFI;
use crate::declare_iterator;
use crate::pe::Section;
use lief_ffi as ffi;

pub struct DataDirectory<'a> {
    ptr: cxx::UniquePtr<ffi::PE_DataDirectory>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub enum Type {
    EXPORT_TABLE,
    IMPORT_TABLE,
    RESOURCE_TABLE,
    EXCEPTION_TABLE,
    CERTIFICATE_TABLE,
    BASE_RELOCATION_TABLE,
    DEBUG_DIR,
    ARCHITECTURE,
    GLOBAL_PTR,
    TLS_TABLE,
    LOAD_CONFIG_TABLE,
    BOUND_IMPORT,
    IAT,
    DELAY_IMPORT_DESCRIPTOR,
    CLR_RUNTIME_HEADER,
    RESERVED,
    UNKNOWN(u32),
}


/// Data directory's types
impl From<u32> for Type {
    fn from(value: u32) -> Self {
        match value {
            0x00000000 => Type::EXPORT_TABLE,
            0x00000001 => Type::IMPORT_TABLE,
            0x00000002 => Type::RESOURCE_TABLE,
            0x00000003 => Type::EXCEPTION_TABLE,
            0x00000004 => Type::CERTIFICATE_TABLE,
            0x00000005 => Type::BASE_RELOCATION_TABLE,
            0x00000006 => Type::DEBUG_DIR,
            0x00000007 => Type::ARCHITECTURE,
            0x00000008 => Type::GLOBAL_PTR,
            0x00000009 => Type::TLS_TABLE,
            0x0000000a => Type::LOAD_CONFIG_TABLE,
            0x0000000b => Type::BOUND_IMPORT,
            0x0000000c => Type::IAT,
            0x0000000d => Type::DELAY_IMPORT_DESCRIPTOR,
            0x0000000e => Type::CLR_RUNTIME_HEADER,
            0x0000000f => Type::RESERVED,
            _ => Type::UNKNOWN(value),

        }
    }
}
impl Into<u32> for Type {
    fn into(self) -> u32 {
        match self {
            Type::EXPORT_TABLE => 0x00000000,
            Type::IMPORT_TABLE => 0x00000001,
            Type::RESOURCE_TABLE => 0x00000002,
            Type::EXCEPTION_TABLE => 0x00000003,
            Type::CERTIFICATE_TABLE => 0x00000004,
            Type::BASE_RELOCATION_TABLE => 0x00000005,
            Type::DEBUG_DIR => 0x00000006,
            Type::ARCHITECTURE => 0x00000007,
            Type::GLOBAL_PTR => 0x00000008,
            Type::TLS_TABLE => 0x00000009,
            Type::LOAD_CONFIG_TABLE => 0x0000000a,
            Type::BOUND_IMPORT => 0x0000000b,
            Type::IAT => 0x0000000c,
            Type::DELAY_IMPORT_DESCRIPTOR => 0x0000000d,
            Type::CLR_RUNTIME_HEADER => 0x0000000e,
            Type::RESERVED => 0x0000000f,
            Type::UNKNOWN(_) => 0x0000000f, // RESERVED

        }
    }
}

impl std::fmt::Debug for DataDirectory<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataDirectory")
            .field("type", &self.get_type())
            .field("rva", &self.rva())
            .field("size", &self.size())
            .field("section", &self.section())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_DataDirectory> for DataDirectory<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_DataDirectory>) -> Self {
        DataDirectory {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DataDirectory<'_> {
    /// The **relative** virtual address where the data referenced by this data directory are
    /// located.
    pub fn rva(&self) -> u32 {
        self.ptr.RVA()
    }
    /// The size of the data referenced by this data directory
    pub fn size(&self) -> u32 {
        self.ptr.size()
    }
    /// The type of the data directory which is defined by its index.
    pub fn get_type(&self) -> Type {
        Type::from(self.ptr.get_type())
    }
    /// The (optional) section in which the data associated with the data directory
    /// are located.
    pub fn section(&self) -> Option<Section> {
        into_optional(self.ptr.section())
    }
}

declare_iterator!(
    DataDirectories,
    DataDirectory<'a>,
    ffi::PE_DataDirectory,
    ffi::PE_Binary,
    ffi::PE_Binary_it_data_directories
);
