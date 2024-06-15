use lief_ffi as ffi;
use std::fmt;
use std::marker::PhantomData;
use bitflags::bitflags;

use crate::to_slice;
use crate::generic;
use crate::common::FromFFI;
use crate::declare_iterator;

/// Structure wich represents an ELF Section
pub struct Section<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_Section>,
    _owner: PhantomData<&'a ()>
}

impl Section<'_> {
    /// Type of the section
    pub fn get_type(&self) -> Type {
        Type::from_value(self.ptr.get_type())
    }

    /// Sections flags
    pub fn flags(&self) -> Flags {
        Flags::from_value(self.ptr.flags())
    }

    /// Section alignment
    pub fn alignment(&self) -> u64 {
        self.ptr.alignment()
    }

    /// Section information.
    /// This meaning of this value depends on the section's type
    pub fn information(&self) -> u64 {
        self.ptr.information()
    }

    /// This function returns the size of an element in the case of a section that contains
    /// an array.
    ///
    /// For instance, the `.dynamic` section contains an array of DynamicEntry. As the
    /// size of the raw C structure of this entry is 0x10 (`sizeof(Elf64_Dyn)`)
    /// in a ELF64, the `entry_size` is set to this value.
    pub fn entry_size(&self) -> u64 {
        self.ptr.entry_size()
    }

    /// Index to another section
    pub fn link(&self) -> u64 {
        self.ptr.link()
    }

    /// Offset in the file where the content of this section is located
    pub fn file_offset(&self) -> u64 {
        self.ptr.file_offset()
    }

    /// Original size of the section (regardless modifications)
    pub fn original_size(&self) -> u64 {
        self.ptr.original_size()
    }

    /// Content of the section as a slice of bytes
    pub fn content(&self) -> &[u8] {
        to_slice!(self.ptr.content());
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Type {
    /// No associated section (inactive entry)
    SHT_NULL,
    /// Program-defined contents.
    PROGBITS,
    /// Symbol table
    SYMTAB,
    /// String table
    STRTAB,
    /// Relocation entries; explicit addends.
    RELA,
    /// Symbol hash table.
    HASH,
    /// Information for dynamic linking.
    DYNAMIC,
    /// Information about the file.
    NOTE,
    /// Data occupies no space in the file.
    NOBITS,
    /// Relocation entries; no explicit addends.
    REL,
    /// Reserved
    SHLIB,
    /// Symbol table.
    DYNSYM,
    /// Pointers to initialization functions.
    INIT_ARRAY,
    /// Pointers to termination functions.
    FINI_ARRAY,
    /// Pointers to pre-init functions.
    PREINIT_ARRAY,
    /// Section group.
    GROUP,
    /// Indices for SHN_XINDEX entries.
    SYMTAB_SHNDX,
    /// Relocation entries; only offsets.
    RELR,
    /// Packed relocations (Android specific).
    ANDROID_REL,
    /// Packed relocations (Android specific).
    ANDROID_RELA,
    /// This section is used to mark symbols as address-significant.
    LLVM_ADDRSIG,
    /// New relr relocations (Android specific).
    ANDROID_RELR,
    /// Object attributes.
    GNU_ATTRIBUTES,
    /// GNU-style hash table.
    GNU_HASH,
    /// GNU version definitions.
    GNU_VERDEF,
    /// GNU version references.
    GNU_VERNEED,
    /// GNU symbol versions table.
    GNU_VERSYM,
    /// Exception Index table
    ARM_EXIDX,
    /// BPABI DLL dynamic linking pre-emption map
    ARM_PREEMPTMAP,
    /// Object file compatibility attributes
    ARM_ATTRIBUTES,
    ARM_DEBUGOVERLAY,
    ARM_OVERLAYSECTION,
    /// Link editor is to sort the entries in this section based on their sizes
    HEX_ORDERED,
    /// Unwind information
    X86_64_UNWIND,
    /// Register usage information
    MIPS_REGINFO,
    /// General options
    MIPS_OPTIONS,
    /// ABI information
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
        const MIPS_NODUPES = 0x401000000;
        const MIPS_NAMES = 0x402000000;
        const MIPS_LOCAL = 0x404000000;
        const MIPS_NOSTRIP = 0x408000000;
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
