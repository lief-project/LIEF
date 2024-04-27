use lief_ffi as ffi;
use std::fmt;
use std::marker::PhantomData;
use bitflags::bitflags;

use crate::to_slice;
use crate::generic;
use crate::common::FromFFI;
use crate::declare_iterator;

pub struct Section<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_Section>,
    _owner: PhantomData<&'a ()>
}

impl Section<'_> {
    pub fn get_type(&self) -> Type {
        Type::from_value(self.ptr.get_type())
    }
    pub fn flags(&self) -> Flags {
        Flags::from_value(self.ptr.flags())
    }
    pub fn alignment(&self) -> u64 {
        self.ptr.alignment()
    }
    pub fn information(&self) -> u64 {
        self.ptr.information()
    }
    pub fn entry_size(&self) -> u64 {
        self.ptr.entry_size()
    }
    pub fn link(&self) -> u64 {
        self.ptr.link()
    }
    pub fn file_offset(&self) -> u64 {
        self.ptr.file_offset()
    }
    pub fn original_size(&self) -> u64 {
        self.ptr.original_size()
    }
    pub fn content(&self) -> &[u8] {
        to_slice!(self.ptr.content());
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Type {
    SHT_NULL,
    PROGBITS,
    SYMTAB,
    STRTAB,
    RELA,
    HASH,
    DYNAMIC,
    NOTE,
    NOBITS,
    REL,
    SHLIB,
    DYNSYM,
    INIT_ARRAY,
    FINI_ARRAY,
    PREINIT_ARRAY,
    GROUP,
    SYMTAB_SHNDX,
    RELR,
    ANDROID_REL,
    ANDROID_RELA,
    LLVM_ADDRSIG,
    ANDROID_RELR,
    GNU_ATTRIBUTES,
    GNU_HASH,
    GNU_VERDEF,
    GNU_VERNEED,
    GNU_VERSYM,
    ARM_EXIDX,
    ARM_PREEMPTMAP,
    ARM_ATTRIBUTES,
    ARM_DEBUGOVERLAY,
    ARM_OVERLAYSECTION,
    HEX_ORDERED,
    X86_64_UNWIND,
    MIPS_REGINFO,
    MIPS_OPTIONS,
    MIPS_ABIFLAGS,
    UNKNOWN(u64),
}

impl Type {
    pub fn from_value(value: u64) -> Self {
        match value {
            0x00000000 => Type::SHT_NULL,
            0x00000001 => Type::PROGBITS,
            0x00000002 => Type::SYMTAB,
            0x00000003 => Type::STRTAB,
            0x00000004 => Type::RELA,
            0x00000005 => Type::HASH,
            0x00000006 => Type::DYNAMIC,
            0x00000007 => Type::NOTE,
            0x00000008 => Type::NOBITS,
            0x00000009 => Type::REL,
            0x0000000a => Type::SHLIB,
            0x0000000b => Type::DYNSYM,
            0x0000000e => Type::INIT_ARRAY,
            0x0000000f => Type::FINI_ARRAY,
            0x00000010 => Type::PREINIT_ARRAY,
            0x00000011 => Type::GROUP,
            0x00000012 => Type::SYMTAB_SHNDX,
            0x00000013 => Type::RELR,
            0x60000001 => Type::ANDROID_REL,
            0x60000002 => Type::ANDROID_RELA,
            0x6fff4c03 => Type::LLVM_ADDRSIG,
            0x6fffff00 => Type::ANDROID_RELR,
            0x6ffffff5 => Type::GNU_ATTRIBUTES,
            0x6ffffff6 => Type::GNU_HASH,
            0x6ffffffd => Type::GNU_VERDEF,
            0x6ffffffe => Type::GNU_VERNEED,
            0x6fffffff => Type::GNU_VERSYM,
            0x170000001 => Type::ARM_EXIDX,
            0x170000002 => Type::ARM_PREEMPTMAP,
            0x170000003 => Type::ARM_ATTRIBUTES,
            0x170000004 => Type::ARM_DEBUGOVERLAY,
            0x170000005 => Type::ARM_OVERLAYSECTION,
            0x270000000 => Type::HEX_ORDERED,
            0x270000001 => Type::X86_64_UNWIND,
            0x370000006 => Type::MIPS_REGINFO,
            0x37000000d => Type::MIPS_OPTIONS,
            0x37000002a => Type::MIPS_ABIFLAGS,
            _ => Type::UNKNOWN(value),

        }
    }
}


bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Flags: u64 {
        const NONE = 0x0;
        const WRITE = 0x1;
        const ALLOC = 0x2;
        const EXECINSTR = 0x4;
        const MERGE = 0x10;
        const STRINGS = 0x20;
        const INFO_LINK = 0x40;
        const LINK_ORDER = 0x80;
        const OS_NONCONFORMING = 0x100;
        const GROUP = 0x200;
        const TLS = 0x400;
        const COMPRESSED = 0x800;
        const GNU_RETAIN = 0x200000;
        const EXCLUDE = 0x80000000;
        const XCORE_SHF_DP_SECTION = 0x110000000;
        const XCORE_SHF_CP_SECTION = 0x120000000;
        const X86_64_LARGE = 0x210000000;
        const HEX_GPREL = 0x310000000;
        const MIPS_NODUPES = 0x410000000;
        const MIPS_NAMES = 0x420000000;
        const MIPS_LOCAL = 0x440000000;
        const MIPS_NOSTRIP = 0x480000000;
        const MIPS_GPREL = 0x410000000;
        const MIPS_MERGE = 0x420000000;
        const MIPS_ADDR = 0x440000000;
        const MIPS_STRING = 0x480000000;
        const ARM_PURECODE = 0x520000000;
    }
}

impl Flags {
    pub fn from_value(value: u64) -> Self {
        Flags::from_bits_truncate(value)
    }
}

impl fmt::Debug for Section<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
       let base = self as &dyn generic::Section;
        f.debug_struct("Section")
            .field("base", &base)
            .field("type", &self.get_type())
            .field("flags", &self.flags())
            .field("alignment", &self.alignment())
            .field("information", &self.information())
            .field("entry_size", &self.entry_size())
            .field("link", &self.link())
            .field("file_offset", &self.file_offset())
            .field("original_size", &self.original_size())
            .finish()

    }
}

impl fmt::Display for Section<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}

impl FromFFI<ffi::ELF_Section> for Section<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_Section>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

impl generic::Section for Section<'_> {
    fn as_generic(&self) -> &ffi::AbstractSection {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

declare_iterator!(Sections, Section<'a>, ffi::ELF_Section, ffi::ELF_Binary, ffi::ELF_Binary_it_sections);
