use super::commands::segment::Segment;
use super::Relocation;
use lief_ffi as ffi;
use std::fmt;
use std::marker::PhantomData;

use crate::common::{into_optional, FromFFI};
use crate::declare_iterator;
use crate::generic;

pub struct Section<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_Section>,
    _owner: PhantomData<&'a ()>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum TYPE {
    REGULAR,
    ZEROFILL,
    CSTRING_LITERALS,
    S_4BYTE_LITERALS,
    S_8BYTE_LITERALS,
    LITERAL_POINTERS,
    NON_LAZY_SYMBOL_POINTERS,
    LAZY_SYMBOL_POINTERS,
    SYMBOL_STUBS,
    MOD_INIT_FUNC_POINTERS,
    MOD_TERM_FUNC_POINTERS,
    COALESCED,
    GB_ZEROFILL,
    INTERPOSING,
    S_16BYTE_LITERALS,
    DTRACE_DOF,
    LAZY_DYLIB_SYMBOL_POINTERS,
    THREAD_LOCAL_REGULAR,
    THREAD_LOCAL_ZEROFILL,
    THREAD_LOCAL_VARIABLES,
    THREAD_LOCAL_VARIABLE_POINTERS,
    THREAD_LOCAL_INIT_FUNCTION_POINTERS,
    UNKNOWN(u64),
}

impl TYPE {
    pub fn from_value(value: u64) -> Self {
        match value {
            0x00000000 => TYPE::REGULAR,
            0x00000001 => TYPE::ZEROFILL,
            0x00000002 => TYPE::CSTRING_LITERALS,
            0x00000003 => TYPE::S_4BYTE_LITERALS,
            0x00000004 => TYPE::S_8BYTE_LITERALS,
            0x00000005 => TYPE::LITERAL_POINTERS,
            0x00000006 => TYPE::NON_LAZY_SYMBOL_POINTERS,
            0x00000007 => TYPE::LAZY_SYMBOL_POINTERS,
            0x00000008 => TYPE::SYMBOL_STUBS,
            0x00000009 => TYPE::MOD_INIT_FUNC_POINTERS,
            0x0000000a => TYPE::MOD_TERM_FUNC_POINTERS,
            0x0000000b => TYPE::COALESCED,
            0x0000000c => TYPE::GB_ZEROFILL,
            0x0000000d => TYPE::INTERPOSING,
            0x0000000e => TYPE::S_16BYTE_LITERALS,
            0x0000000f => TYPE::DTRACE_DOF,
            0x00000010 => TYPE::LAZY_DYLIB_SYMBOL_POINTERS,
            0x00000011 => TYPE::THREAD_LOCAL_REGULAR,
            0x00000012 => TYPE::THREAD_LOCAL_ZEROFILL,
            0x00000013 => TYPE::THREAD_LOCAL_VARIABLES,
            0x00000014 => TYPE::THREAD_LOCAL_VARIABLE_POINTERS,
            0x00000015 => TYPE::THREAD_LOCAL_INIT_FUNCTION_POINTERS,
            _ => TYPE::UNKNOWN(value),
        }
    }
}

impl Section<'_> {
    pub fn segment_name(&self) -> String {
        self.ptr.segment_name().to_string()
    }
    pub fn address(&self) -> u64 {
        self.ptr.address()
    }

    pub fn alignment(&self) -> u32 {
        self.ptr.alignment()
    }

    pub fn relocation_offset(&self) -> u32 {
        self.ptr.relocation_offset()
    }

    pub fn numberof_relocations(&self) -> u32 {
        self.ptr.numberof_relocations()
    }

    pub fn raw_flags(&self) -> u32 {
        self.ptr.raw_flags()
    }

    pub fn flags(&self) -> u32 {
        self.ptr.flags()
    }

    pub fn section_type(&self) -> TYPE {
        TYPE::from_value(self.ptr.section_type())
    }

    pub fn reserved1(&self) -> u32 {
        self.ptr.reserved1()
    }

    pub fn reserved2(&self) -> u32 {
        self.ptr.reserved2()
    }

    pub fn reserved3(&self) -> u32 {
        self.ptr.reserved3()
    }

    pub fn segment(&self) -> Option<Segment> {
        into_optional(self.ptr.segment())
    }

    pub fn relocations(&self) -> Relocations {
        Relocations::new(self.ptr.relocations())
    }
}

impl fmt::Debug for Section<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base = self as &dyn generic::Section;
        f.debug_struct("Section")
            .field("base", &base)
            .field("segment_name", &self.segment_name())
            .field("address", &self.address())
            .field("alignment", &self.alignment())
            .field("relocation_offset", &self.relocation_offset())
            .field("numberof_relocations", &self.numberof_relocations())
            .field("raw_flags", &self.raw_flags())
            .field("flags", &self.flags())
            .field("type", &self.section_type())
            .field("reserved1", &self.reserved1())
            .field("reserved2", &self.reserved2())
            .field("reserved3", &self.reserved3())
            .finish()
    }
}

impl<'a> FromFFI<ffi::MachO_Section> for Section<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::MachO_Section>) -> Self {
        Self {
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
    ffi::MachO_Section,
    ffi::MachO_Binary,
    ffi::MachO_Binary_it_sections
);
declare_iterator!(
    Relocations,
    Relocation<'a>,
    ffi::MachO_Relocation,
    ffi::MachO_Section,
    ffi::MachO_Section_it_relocations
);
