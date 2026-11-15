//! PE Data Directory module

use std::marker::PhantomData;

use crate::common::FromFFI;
use crate::common::into_optional;
use crate::pe::Section;
use crate::to_slice;
use crate::{declare_iterator, enum_from_int};

use lief_ffi as ffi;

pub struct DataDirectory<'a> {
    ptr: cxx::UniquePtr<ffi::PE_DataDirectory>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    /// Data directory's types
    Type: u32 {
        EXPORT_TABLE = 0x00000000,
        IMPORT_TABLE = 0x00000001,
        RESOURCE_TABLE = 0x00000002,
        EXCEPTION_TABLE = 0x00000003,
        CERTIFICATE_TABLE = 0x00000004,
        BASE_RELOCATION_TABLE = 0x00000005,
        DEBUG_DIR = 0x00000006,
        ARCHITECTURE = 0x00000007,
        GLOBAL_PTR = 0x00000008,
        TLS_TABLE = 0x00000009,
        LOAD_CONFIG_TABLE = 0x0000000a,
        BOUND_IMPORT = 0x0000000b,
        IAT = 0x0000000c,
        DELAY_IMPORT_DESCRIPTOR = 0x0000000d,
        CLR_RUNTIME_HEADER = 0x0000000e,
        RESERVED = 0x0000000f,
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

impl FromFFI<ffi::PE_DataDirectory> for DataDirectory<'_> {
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
    pub fn section(&self) -> Option<Section<'_>> {
        into_optional(self.ptr.section())
    }

    /// Content bytes wraped with this data directory
    pub fn content(&self) -> &[u8] {
        to_slice!(self.ptr.content());
    }
}

declare_iterator!(
    DataDirectories,
    DataDirectory<'a>,
    ffi::PE_DataDirectory,
    ffi::PE_Binary,
    ffi::PE_Binary_it_data_directories
);
