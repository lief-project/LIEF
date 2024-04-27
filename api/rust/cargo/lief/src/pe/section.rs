use std::marker::PhantomData;

use lief_ffi as ffi;

use crate::declare_iterator;
use crate::to_slice;
use crate::{common::FromFFI, generic};
use bitflags::bitflags;

pub struct Section<'a> {
    ptr: cxx::UniquePtr<ffi::PE_Section>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Characteristics: u64 {
        const TYPE_NO_PAD = 0x8;
        const CNT_CODE = 0x20;
        const CNT_INITIALIZED_DATA = 0x40;
        const CNT_UNINITIALIZED_DATA = 0x80;
        const LNK_OTHER = 0x100;
        const LNK_INFO = 0x200;
        const LNK_REMOVE = 0x800;
        const LNK_COMDAT = 0x1000;
        const GPREL = 0x8000;
        const MEM_PURGEABLE = 0x10000;
        const MEM_16BIT = 0x20000;
        const MEM_LOCKED = 0x40000;
        const MEM_PRELOAD = 0x80000;
        const ALIGN_1BYTES = 0x100000;
        const ALIGN_2BYTES = 0x200000;
        const ALIGN_4BYTES = 0x300000;
        const ALIGN_8BYTES = 0x400000;
        const ALIGN_16BYTES = 0x500000;
        const ALIGN_32BYTES = 0x600000;
        const ALIGN_64BYTES = 0x700000;
        const ALIGN_128BYTES = 0x800000;
        const ALIGN_256BYTES = 0x900000;
        const ALIGN_512BYTES = 0xa00000;
        const ALIGN_1024BYTES = 0xb00000;
        const ALIGN_2048BYTES = 0xc00000;
        const ALIGN_4096BYTES = 0xd00000;
        const ALIGN_8192BYTES = 0xe00000;
        const LNK_NRELOC_OVFL = 0x1000000;
        const MEM_DISCARDABLE = 0x2000000;
        const MEM_NOT_CACHED = 0x4000000;
        const MEM_NOT_PAGED = 0x8000000;
        const MEM_SHARED = 0x10000000;
        const MEM_EXECUTE = 0x20000000;
        const MEM_READ = 0x40000000;
        const MEM_WRITE = 0x80000000;
    }
}

impl Characteristics {
    pub fn from_value(value: u64) -> Self {
        Characteristics::from_bits_truncate(value)
    }
}

impl Section<'_> {
    pub fn sizeof_raw_data(&self) -> u32 {
        self.ptr.sizeof_raw_data()
    }
    pub fn virtual_size(&self) -> u32 {
        self.ptr.virtual_size()
    }
    pub fn pointerto_raw_data(&self) -> u32 {
        self.ptr.pointerto_raw_data()
    }
    pub fn pointerto_relocation(&self) -> u32 {
        self.ptr.pointerto_relocation()
    }
    pub fn pointerto_line_numbers(&self) -> u32 {
        self.ptr.pointerto_line_numbers()
    }
    pub fn numberof_relocations(&self) -> u32 {
        self.ptr.numberof_relocations()
    }
    pub fn numberof_line_numbers(&self) -> u32 {
        self.ptr.numberof_line_numbers()
    }
    pub fn characteristics(&self) -> Characteristics {
        Characteristics::from_value(self.ptr.characteristics())
    }
    pub fn padding(&self) -> &[u8] {
        to_slice!(self.ptr.padding());
    }
}

impl std::fmt::Debug for Section<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn generic::Section;
        f.debug_struct("Section")
            .field("base", &base)
            .field("sizeof_raw_data", &self.sizeof_raw_data())
            .field("virtual_size", &self.virtual_size())
            .field("pointerto_raw_data", &self.pointerto_raw_data())
            .field("pointerto_relocation", &self.pointerto_relocation())
            .field("pointerto_line_numbers", &self.pointerto_line_numbers())
            .field("numberof_relocations", &self.numberof_relocations())
            .field("numberof_line_numbers", &self.numberof_line_numbers())
            .field("characteristics", &self.characteristics())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_Section> for Section<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_Section>) -> Self {
        Section {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl generic::Section for Section<'_> {
    fn as_generic(&self) -> &ffi::AbstractSection {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

declare_iterator!(
    Sections,
    Section<'a>,
    ffi::PE_Section,
    ffi::PE_Binary,
    ffi::PE_Binary_it_sections
);
