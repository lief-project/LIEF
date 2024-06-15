use super::commands::segment::Segment;
use super::Relocation;
use lief_ffi as ffi;
use std::fmt;
use std::marker::PhantomData;

use crate::common::{into_optional, FromFFI};
use crate::declare_iterator;
use crate::generic;

use bitflags::bitflags;

pub struct Section<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_Section>,
    _owner: PhantomData<&'a ()>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Type {
    /// Regular section.
    REGULAR,
    /// Zero fill on demand section.
    ZEROFILL,
    /// Section with literal C strings.
    CSTRING_LITERALS,
    /// Section with 4 byte literals.
    S_4BYTE_LITERALS,
    /// Section with 8 byte literals.
    S_8BYTE_LITERALS,
    /// Section with pointers to literals.
    LITERAL_POINTERS,
    /// Section with non-lazy symbol pointers.
    NON_LAZY_SYMBOL_POINTERS,
    /// Section with lazy symbol pointers.
    LAZY_SYMBOL_POINTERS,
    /// Section with symbol stubs, byte size of stub in the Reserved2 field.
    SYMBOL_STUBS,
    /// Section with only function pointers for initialization.
    MOD_INIT_FUNC_POINTERS,
    /// Section with only function pointers for termination.
    MOD_TERM_FUNC_POINTERS,
    /// Section contains symbols that are to be coalesced.
    COALESCED,
    /// Zero fill on demand section (that can be larger than 4 gigabytes).
    GB_ZEROFILL,
    /// Section with only pairs of function pointers for interposing.
    INTERPOSING,
    /// Section with only 16 byte literals.
    S_16BYTE_LITERALS,
    /// Section contains DTrace Object Format.
    DTRACE_DOF,
    /// Section with lazy symbol pointers to lazy loaded dylibs.
    LAZY_DYLIB_SYMBOL_POINTERS,
    /// Thread local data section.
    THREAD_LOCAL_REGULAR,
    /// Thread local zerofill section.
    THREAD_LOCAL_ZEROFILL,
    /// Section with thread local variable structure data.
    THREAD_LOCAL_VARIABLES,
    /// Section with pointers to thread local structures.
    THREAD_LOCAL_VARIABLE_POINTERS,
    /// Section with thread local variable initialization pointers to functions.
    THREAD_LOCAL_INIT_FUNCTION_POINTERS,
    /// Section with 32-bit offsets to initializer functions
    INIT_FUNC_OFFSETS,
    UNKNOWN(u64),
}

impl From<u64> for Type {
    fn from(value: u64) -> Self {
        match value {
            0x00000000 => Type::REGULAR,
            0x00000001 => Type::ZEROFILL,
            0x00000002 => Type::CSTRING_LITERALS,
            0x00000003 => Type::S_4BYTE_LITERALS,
            0x00000004 => Type::S_8BYTE_LITERALS,
            0x00000005 => Type::LITERAL_POINTERS,
            0x00000006 => Type::NON_LAZY_SYMBOL_POINTERS,
            0x00000007 => Type::LAZY_SYMBOL_POINTERS,
            0x00000008 => Type::SYMBOL_STUBS,
            0x00000009 => Type::MOD_INIT_FUNC_POINTERS,
            0x0000000a => Type::MOD_TERM_FUNC_POINTERS,
            0x0000000b => Type::COALESCED,
            0x0000000c => Type::GB_ZEROFILL,
            0x0000000d => Type::INTERPOSING,
            0x0000000e => Type::S_16BYTE_LITERALS,
            0x0000000f => Type::DTRACE_DOF,
            0x00000010 => Type::LAZY_DYLIB_SYMBOL_POINTERS,
            0x00000011 => Type::THREAD_LOCAL_REGULAR,
            0x00000012 => Type::THREAD_LOCAL_ZEROFILL,
            0x00000013 => Type::THREAD_LOCAL_VARIABLES,
            0x00000014 => Type::THREAD_LOCAL_VARIABLE_POINTERS,
            0x00000015 => Type::THREAD_LOCAL_INIT_FUNCTION_POINTERS,
            0x00000016 => Type::INIT_FUNC_OFFSETS,
            _ => Type::UNKNOWN(value),
        }
    }
}


bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Flags: u64 {
        const PURE_INSTRUCTIONS = 0x80000000;
        const NO_TOC = 0x40000000;
        const STRIP_STATIC_SYMS = 0x20000000;
        const NO_DEAD_STRIP = 0x10000000;
        const LIVE_SUPPORT = 0x8000000;
        const SELF_MODIFYING_CODE = 0x4000000;
        const DEBUG_INFO = 0x2000000;
        const SOME_INSTRUCTIONS = 0x400;
        const EXT_RELOC = 0x200;
        const LOC_RELOC = 0x100;
    }
}


impl From<u64> for Flags {
    fn from(value: u64) -> Self {
        Flags::from_bits_truncate(value)
    }
}
impl From<Flags> for u64 {
    fn from(value: Flags) -> Self {
        value.bits()
    }
}
impl std::fmt::Display for Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

impl Section<'_> {
    /// Name of the segment that owns this section
    pub fn segment_name(&self) -> String {
        self.ptr.segment_name().to_string()
    }

    /// Virtual base address of this section
    pub fn address(&self) -> u64 {
        self.ptr.address()
    }

    /// Section alignment as a power of 2
    pub fn alignment(&self) -> u32 {
        self.ptr.alignment()
    }


    /// Offset of the relocation table. This value should be 0
    /// for executable and libraries as the relocations are managed by
    /// [`crate::macho::Relocation::Dyld`] or [`crate::macho::Relocation::Fixup`]
    ///
    /// On the other hand, for object files (`.o`) this value should not be 0 (c.f. [`crate::macho::Relocation::Object`])
    pub fn relocation_offset(&self) -> u32 {
        self.ptr.relocation_offset()
    }

    /// Number of relocations associated with this section
    pub fn numberof_relocations(&self) -> u32 {
        self.ptr.numberof_relocations()
    }

    pub fn raw_flags(&self) -> u32 {
        self.ptr.raw_flags()
    }

    /// Section's flags masked with `SECTION_FLAGS_MASK`
    pub fn flags(&self) -> Flags {
        Flags::from_bits_truncate(self.ptr.flags())
    }

    /// Type of the section. This value can help to determine the purpose of the section
    pub fn section_type(&self) -> Type {
        Type::from(self.ptr.section_type())
    }

    /// According to the official `loader.h` file, this value is reserved
    /// for *offset* or *index*
    pub fn reserved1(&self) -> u32 {
        self.ptr.reserved1()
    }

    /// According to the official `loader.h` file, this value is reserved
    /// for *count* or *sizeof*
    pub fn reserved2(&self) -> u32 {
        self.ptr.reserved2()
    }

    /// This value is only present for 64 bits Mach-O files. In that case,
    /// the value is *reserved*.
    pub fn reserved3(&self) -> u32 {
        self.ptr.reserved3()
    }

    /// Segment bound to this section
    pub fn segment(&self) -> Option<Segment> {
        into_optional(self.ptr.segment())
    }

    /// Iterator over the [`crate::macho::Relocation`] associated with thi section
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
