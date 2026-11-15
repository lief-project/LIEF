use bitflags::bitflags;
use lief_ffi as ffi;
use std::fmt;
use std::marker::PhantomData;
use std::pin::Pin;

use crate::common::FromFFI;
use crate::generic;
use crate::to_slice;
use crate::{declare_iterator, enum_from_int};

/// Structure which represents an ELF Section
pub struct Section<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_Section>,
    _owner: PhantomData<&'a ()>,
}

impl Section<'_> {
    /// Create a new section
    pub fn new() -> Section<'static> {
        Section::from_ffi(ffi::ELF_Section::create())
    }

    /// Create a new section with the given name
    pub fn new_with_name(name: &str) -> Section<'static> {
        cxx::let_cxx_string!(__cxx_name = name);
        Section::from_ffi(ffi::ELF_Section::create_with_name(&__cxx_name))
    }

    /// Create a new section with the given name and content
    pub fn new_with_content(name: &str, content: &[u8]) -> Section<'static> {
        cxx::let_cxx_string!(__cxx_name = name);
        unsafe {
            Section::from_ffi(ffi::ELF_Section::create_with_content(
                &__cxx_name,
                content.as_ptr(),
                content.len(),
            ))
        }
    }

    /// Type of the section
    pub fn get_type(&self) -> Type {
        Type::from(self.ptr.get_type())
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
    /// in an ELF64, the `entry_size` is set to this value.
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

    /// Change the type of the section
    pub fn set_type(&mut self, ty: Type) {
        self.ptr.pin_mut().set_type(ty.into());
    }

    /// Change the flags of the section
    pub fn set_flags(&mut self, flags: Flags) {
        self.ptr.pin_mut().set_flags(flags.bits());
    }

    /// Change the alignment of the section
    pub fn set_alignment(&mut self, alignment: u64) {
        self.ptr.pin_mut().set_alignment(alignment);
    }
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    #[derive(PartialOrd, Ord)]
    Type: u64 {
        /// No associated section (inactive entry)
        SHT_NULL = 0x00000000,
        /// Program-defined contents.
        PROGBITS = 0x00000001,
        /// Symbol table
        SYMTAB = 0x00000002,
        /// String table
        STRTAB = 0x00000003,
        /// Relocation entries; explicit addends.
        RELA = 0x00000004,
        /// Symbol hash table.
        HASH = 0x00000005,
        /// Information for dynamic linking.
        DYNAMIC = 0x00000006,
        /// Information about the file.
        NOTE = 0x00000007,
        /// Data occupies no space in the file.
        NOBITS = 0x00000008,
        /// Relocation entries; no explicit addends.
        REL = 0x00000009,
        /// Reserved
        SHLIB = 0x0000000a,
        /// Symbol table.
        DYNSYM = 0x0000000b,
        /// Pointers to initialization functions.
        INIT_ARRAY = 0x0000000e,
        /// Pointers to termination functions.
        FINI_ARRAY = 0x0000000f,
        /// Pointers to pre-init functions.
        PREINIT_ARRAY = 0x00000010,
        /// Section group.
        GROUP = 0x00000011,
        /// Indices for SHN_XINDEX entries.
        SYMTAB_SHNDX = 0x00000012,
        /// Relocation entries; only offsets.
        RELR = 0x00000013,
        /// Packed relocations (Android specific).
        ANDROID_REL = 0x60000001,
        /// Packed relocations (Android specific).
        ANDROID_RELA = 0x60000002,
        /// This section is used to mark symbols as address-significant.
        LLVM_ADDRSIG = 0x6fff4c03,
        /// New relr relocations (Android specific).
        ANDROID_RELR = 0x6fffff00,
        /// Object attributes.
        GNU_ATTRIBUTES = 0x6ffffff5,
        /// GNU-style hash table.
        GNU_HASH = 0x6ffffff6,
        /// GNU version definitions.
        GNU_VERDEF = 0x6ffffffd,
        /// GNU version references.
        GNU_VERNEED = 0x6ffffffe,
        /// GNU symbol versions table.
        GNU_VERSYM = 0x6fffffff,
        /// Exception Index table
        ARM_EXIDX = 0x170000001,
        /// BPABI DLL dynamic linking pre-emption map
        ARM_PREEMPTMAP = 0x170000002,
        /// Object file compatibility attributes
        ARM_ATTRIBUTES = 0x170000003,
        ARM_DEBUGOVERLAY = 0x170000004,
        ARM_OVERLAYSECTION = 0x170000005,
        /// Link editor is to sort the entries in this section based on their sizes
        HEX_ORDERED = 0x270000000,
        /// Unwind information
        X86_64_UNWIND = 0x270000001,
        /// Register usage information
        MIPS_REGINFO = 0x370000006,
        /// General options
        MIPS_OPTIONS = 0x37000000d,
        /// ABI information
        MIPS_ABIFLAGS = 0x37000002a,
        /// RISC-V Attribute
        RISCV_ATTRIBUTES = 0x470000003,
        /// AArch64 build attributes
        AARCH64_ATTRIBUTES = 0x570000003,
        /// AArch64 PAuth relocations
        AARCH64_AUTH_RELR = 0x570000004,
        /// AArch64 memory tagging globals (static)
        AARCH64_MEMTAG_GLOBALS_STATIC = 0x570000007,
        /// AArch64 memory tagging globals (dynamic)
        AARCH64_MEMTAG_GLOBALS_DYNAMIC = 0x570000008,
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
        const AARCH64_PURECODE = 0x620000000;
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
            _owner: PhantomData,
        }
    }
}

impl crate::common::AsFFI<ffi::ELF_Section> for Section<'_> {
    fn as_ffi(&self) -> &ffi::ELF_Section {
        self.ptr.as_ref().unwrap()
    }

    fn as_mut_ffi(&mut self) -> Pin<&mut ffi::ELF_Section> {
        self.ptr.pin_mut()
    }
}

impl generic::Section for Section<'_> {
    fn as_generic(&self) -> &ffi::AbstractSection {
        self.ptr.as_ref().unwrap().as_ref()
    }

    fn as_generic_mut(&mut self) -> Pin<&mut ffi::AbstractSection> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref() as *const ffi::AbstractSection
                    as *mut ffi::AbstractSection)
                    .as_mut()
                    .unwrap()
            })
        }
    }
}

declare_iterator!(
    Sections,
    Section<'a>,
    ffi::ELF_Section,
    ffi::ELF_Binary,
    ffi::ELF_Binary_it_sections
);
