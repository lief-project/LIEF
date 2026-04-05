use super::commands::segment::Segment;
use super::thread_local_variables::ThreadLocalVariables;
use super::Relocation;
use lief_ffi as ffi;
use std::fmt;
use std::pin::Pin;
use std::marker::PhantomData;

use crate::common::{into_optional, FromFFI};
use crate::declare_iterator;
use crate::generic;

use bitflags::bitflags;

/// Enum that wraps all the Mach-O section types, dispatching to the
/// appropriate concrete type when extra semantics are available.
#[derive(Debug)]
pub enum Section<'a> {
    /// A section without additional specialization.
    Generic(Generic<'a>),

    /// A section whose type is [`Type::THREAD_LOCAL_VARIABLES`], providing access
    /// to thread-local variable descriptors.
    ThreadLocalVariables(ThreadLocalVariables<'a>),
}

pub struct Generic<'a> {
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

/// Trait shared by **all** Mach-O section types in the [`Section`] enum.
pub trait MachOSection {
    #[doc(hidden)]
    fn as_base(&self) -> &ffi::MachO_Section;

    #[doc(hidden)]
    fn as_mut_base(&mut self) -> Pin<&mut ffi::MachO_Section>;

    /// Name of the segment that owns this section
    fn segment_name(&self) -> String {
        self.as_base().segment_name().to_string()
    }

    /// Virtual base address of this section
    fn address(&self) -> u64 {
        self.as_base().address()
    }

    /// Section alignment as a power of 2
    fn alignment(&self) -> u32 {
        self.as_base().alignment()
    }

    /// Offset of the relocation table. This value should be 0
    /// for executable and libraries as the relocations are managed by
    /// [`crate::macho::Relocation::Dyld`] or [`crate::macho::Relocation::Fixup`]
    ///
    /// On the other hand, for object files (`.o`) this value should not be 0 (c.f. [`crate::macho::Relocation::Object`])
    fn relocation_offset(&self) -> u32 {
        self.as_base().relocation_offset()
    }

    /// Number of relocations associated with this section
    fn numberof_relocations(&self) -> u32 {
        self.as_base().numberof_relocations()
    }

    fn raw_flags(&self) -> u32 {
        self.as_base().raw_flags()
    }

    /// Section's flags masked with `SECTION_FLAGS_MASK`
    fn flags(&self) -> Flags {
        Flags::from_bits_truncate(self.as_base().flags())
    }

    /// Type of the section. This value can help to determine the purpose of the section
    fn section_type(&self) -> Type {
        Type::from(self.as_base().section_type())
    }

    /// According to the official `loader.h` file, this value is reserved
    /// for *offset* or *index*
    fn reserved1(&self) -> u32 {
        self.as_base().reserved1()
    }

    /// According to the official `loader.h` file, this value is reserved
    /// for *count* or *sizeof*
    fn reserved2(&self) -> u32 {
        self.as_base().reserved2()
    }

    /// This value is only present for 64 bits Mach-O files. In that case,
    /// the value is *reserved*.
    fn reserved3(&self) -> u32 {
        self.as_base().reserved3()
    }

    /// Segment bound to this section
    fn segment(&self) -> Option<Segment<'_>> {
        into_optional(self.as_base().segment())
    }

    /// Iterator over the [`crate::macho::Relocation`] associated with this section
    fn relocations(&self) -> Relocations<'_> {
        Relocations::new(self.as_base().relocations())
    }
}

impl MachOSection for Generic<'_> {
    fn as_base(&self) -> &ffi::MachO_Section {
        self.ptr.as_ref().unwrap()
    }

    fn as_mut_base(&mut self) -> Pin<&mut ffi::MachO_Section> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap() as *const ffi::MachO_Section
                    as *mut ffi::MachO_Section)
                    .as_mut()
                    .unwrap()
            })
        }
    }
}

impl MachOSection for Section<'_> {
    fn as_base(&self) -> &ffi::MachO_Section {
        match self {
            Section::Generic(s) => s.as_base(),
            Section::ThreadLocalVariables(s) => s.as_base(),
        }
    }

    fn as_mut_base(&mut self) -> Pin<&mut ffi::MachO_Section> {
        match self {
            Section::Generic(s) => s.as_mut_base(),
            Section::ThreadLocalVariables(s) => s.as_mut_base(),
        }
    }
}

impl fmt::Debug for Generic<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base = self as &dyn generic::Section;
        f.debug_struct("Generic")
            .field("base", &base)
            .field("segment_name", &MachOSection::segment_name(self))
            .field("address", &MachOSection::address(self))
            .field("alignment", &MachOSection::alignment(self))
            .field("relocation_offset", &MachOSection::relocation_offset(self))
            .field("numberof_relocations", &MachOSection::numberof_relocations(self))
            .field("raw_flags", &MachOSection::raw_flags(self))
            .field("flags", &MachOSection::flags(self))
            .field("type", &MachOSection::section_type(self))
            .field("reserved1", &MachOSection::reserved1(self))
            .field("reserved2", &MachOSection::reserved2(self))
            .field("reserved3", &MachOSection::reserved3(self))
            .finish()
    }
}

impl<'a> FromFFI<ffi::MachO_Section> for Generic<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::MachO_Section>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl<'a> FromFFI<ffi::MachO_Section> for Section<'a> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::MachO_Section>) -> Self {
        unsafe {
            let sec_ref = ffi_entry.as_ref().unwrap();
            if ffi::MachO_ThreadLocalVariables::classof(sec_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Section>;
                    type To = cxx::UniquePtr<ffi::MachO_ThreadLocalVariables>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Section::ThreadLocalVariables(ThreadLocalVariables::from_ffi(raw))
            } else {
                Section::Generic(Generic::from_ffi(ffi_entry))
            }
        }
    }
}

impl generic::Section for Generic<'_> {
    fn as_generic(&self) -> &ffi::AbstractSection {
        self.as_base().as_ref()
    }

    fn as_generic_mut(&mut self) -> Pin<&mut ffi::AbstractSection> {
        unsafe {
            Pin::new_unchecked({
                (self.as_generic() as *const ffi::AbstractSection
                    as *mut ffi::AbstractSection)
                    .as_mut()
                    .unwrap()
            })
        }
    }
}

impl generic::Section for Section<'_> {
    fn as_generic(&self) -> &ffi::AbstractSection {
        match self {
            Section::Generic(s) => s.as_generic(),
            Section::ThreadLocalVariables(s) => s.as_generic(),
        }
    }

    fn as_generic_mut(&mut self) -> Pin<&mut ffi::AbstractSection> {
        match self {
            Section::Generic(s) => s.as_generic_mut(),
            Section::ThreadLocalVariables(s) => s.as_generic_mut(),
        }
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
