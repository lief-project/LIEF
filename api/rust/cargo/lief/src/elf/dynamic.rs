use std::marker::PhantomData;

use lief_ffi as ffi;
use crate::common::FromFFI;
use crate::declare_iterator;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Tag {
    DT_NULL,
    NEEDED,
    PLTRELSZ,
    PLTGOT,
    HASH,
    STRTAB,
    SYMTAB,
    RELA,
    RELASZ,
    RELAENT,
    STRSZ,
    SYMENT,
    INIT,
    FINI,
    SONAME,
    RPATH,
    SYMBOLIC,
    REL,
    RELSZ,
    RELENT,
    PLTREL,
    DEBUG_TAG,
    TEXTREL,
    JMPREL,
    BIND_NOW,
    INIT_ARRAY,
    FINI_ARRAY,
    INIT_ARRAYSZ,
    FINI_ARRAYSZ,
    RUNPATH,
    FLAGS,
    PREINIT_ARRAY,
    PREINIT_ARRAYSZ,
    SYMTAB_SHNDX,
    RELRSZ,
    RELR,
    RELRENT,
    GNU_HASH,
    RELACOUNT,
    RELCOUNT,
    FLAGS_1,
    VERSYM,
    VERDEF,
    VERDEFNUM,
    VERNEED,
    VERNEEDNUM,
    ANDROID_REL_OFFSET,
    ANDROID_REL_SIZE,
    ANDROID_REL,
    ANDROID_RELSZ,
    ANDROID_RELA,
    ANDROID_RELASZ,
    ANDROID_RELR,
    ANDROID_RELRSZ,
    ANDROID_RELRENT,
    ANDROID_RELRCOUNT,
    MIPS_RLD_VERSION,
    MIPS_TIME_STAMP,
    MIPS_ICHECKSUM,
    MIPS_IVERSION,
    MIPS_FLAGS,
    MIPS_BASE_ADDRESS,
    MIPS_MSYM,
    MIPS_CONFLICT,
    MIPS_LIBLIST,
    MIPS_LOCAL_GOTNO,
    MIPS_CONFLICTNO,
    MIPS_LIBLISTNO,
    MIPS_SYMTABNO,
    MIPS_UNREFEXTNO,
    MIPS_GOTSYM,
    MIPS_HIPAGENO,
    MIPS_RLD_MAP,
    MIPS_DELTA_CLASS,
    MIPS_DELTA_CLASS_NO,
    MIPS_DELTA_INSTANCE,
    MIPS_DELTA_INSTANCE_NO,
    MIPS_DELTA_RELOC,
    MIPS_DELTA_RELOC_NO,
    MIPS_DELTA_SYM,
    MIPS_DELTA_SYM_NO,
    MIPS_DELTA_CLASSSYM,
    MIPS_DELTA_CLASSSYM_NO,
    MIPS_CXX_FLAGS,
    MIPS_PIXIE_INIT,
    MIPS_SYMBOL_LIB,
    MIPS_LOCALPAGE_GOTIDX,
    MIPS_LOCAL_GOTIDX,
    MIPS_HIDDEN_GOTIDX,
    MIPS_PROTECTED_GOTIDX,
    MIPS_OPTIONS,
    MIPS_INTERFACE,
    MIPS_DYNSTR_ALIGN,
    MIPS_INTERFACE_SIZE,
    MIPS_RLD_TEXT_RESOLVE_ADDR,
    MIPS_PERF_SUFFIX,
    MIPS_COMPACT_SIZE,
    MIPS_GP_VALUE,
    MIPS_AUX_DYNAMIC,
    MIPS_PLTGOT,
    MIPS_RWPLT,
    MIPS_RLD_MAP_REL,
    MIPS_XHASH,
    AARCH64_BTI_PLT,
    AARCH64_PAC_PLT,
    AARCH64_VARIANT_PCS,
    AARCH64_MEMTAG_MODE,
    AARCH64_MEMTAG_HEAP,
    AARCH64_MEMTAG_STACK,
    AARCH64_MEMTAG_GLOBALS,
    AARCH64_MEMTAG_GLOBALSSZ,
    HEXAGON_SYMSZ,
    HEXAGON_VER,
    HEXAGON_PLT,
    PPC_GOT,
    PPC_OPT,
    PPC64_GLINK,
    PPC64_OPT,
    RISCV_VARIANT_CC,
    UNKNOWN(u64),
}

impl From<u64> for Tag {
    fn from(value: u64) -> Self {
        match value {
            0x00000000 => Tag::DT_NULL,
            0x00000001 => Tag::NEEDED,
            0x00000002 => Tag::PLTRELSZ,
            0x00000003 => Tag::PLTGOT,
            0x00000004 => Tag::HASH,
            0x00000005 => Tag::STRTAB,
            0x00000006 => Tag::SYMTAB,
            0x00000007 => Tag::RELA,
            0x00000008 => Tag::RELASZ,
            0x00000009 => Tag::RELAENT,
            0x0000000a => Tag::STRSZ,
            0x0000000b => Tag::SYMENT,
            0x0000000c => Tag::INIT,
            0x0000000d => Tag::FINI,
            0x0000000e => Tag::SONAME,
            0x0000000f => Tag::RPATH,
            0x00000010 => Tag::SYMBOLIC,
            0x00000011 => Tag::REL,
            0x00000012 => Tag::RELSZ,
            0x00000013 => Tag::RELENT,
            0x00000014 => Tag::PLTREL,
            0x00000015 => Tag::DEBUG_TAG,
            0x00000016 => Tag::TEXTREL,
            0x00000017 => Tag::JMPREL,
            0x00000018 => Tag::BIND_NOW,
            0x00000019 => Tag::INIT_ARRAY,
            0x0000001a => Tag::FINI_ARRAY,
            0x0000001b => Tag::INIT_ARRAYSZ,
            0x0000001c => Tag::FINI_ARRAYSZ,
            0x0000001d => Tag::RUNPATH,
            0x0000001e => Tag::FLAGS,
            0x00000020 => Tag::PREINIT_ARRAY,
            0x00000021 => Tag::PREINIT_ARRAYSZ,
            0x00000022 => Tag::SYMTAB_SHNDX,
            0x00000023 => Tag::RELRSZ,
            0x00000024 => Tag::RELR,
            0x00000025 => Tag::RELRENT,
            0x6ffffef5 => Tag::GNU_HASH,
            0x6ffffff9 => Tag::RELACOUNT,
            0x6ffffffa => Tag::RELCOUNT,
            0x6ffffffb => Tag::FLAGS_1,
            0x6ffffff0 => Tag::VERSYM,
            0x6ffffffc => Tag::VERDEF,
            0x6ffffffd => Tag::VERDEFNUM,
            0x6ffffffe => Tag::VERNEED,
            0x6fffffff => Tag::VERNEEDNUM,
            0x6000000d => Tag::ANDROID_REL_OFFSET,
            0x6000000e => Tag::ANDROID_REL_SIZE,
            0x6000000f => Tag::ANDROID_REL,
            0x60000010 => Tag::ANDROID_RELSZ,
            0x60000011 => Tag::ANDROID_RELA,
            0x60000012 => Tag::ANDROID_RELASZ,
            0x6fffe000 => Tag::ANDROID_RELR,
            0x6fffe001 => Tag::ANDROID_RELRSZ,
            0x6fffe003 => Tag::ANDROID_RELRENT,
            0x6fffe005 => Tag::ANDROID_RELRCOUNT,
            0x170000001 => Tag::MIPS_RLD_VERSION,
            0x170000002 => Tag::MIPS_TIME_STAMP,
            0x170000003 => Tag::MIPS_ICHECKSUM,
            0x170000004 => Tag::MIPS_IVERSION,
            0x170000005 => Tag::MIPS_FLAGS,
            0x170000006 => Tag::MIPS_BASE_ADDRESS,
            0x170000007 => Tag::MIPS_MSYM,
            0x170000008 => Tag::MIPS_CONFLICT,
            0x170000009 => Tag::MIPS_LIBLIST,
            0x17000000a => Tag::MIPS_LOCAL_GOTNO,
            0x17000000b => Tag::MIPS_CONFLICTNO,
            0x170000010 => Tag::MIPS_LIBLISTNO,
            0x170000011 => Tag::MIPS_SYMTABNO,
            0x170000012 => Tag::MIPS_UNREFEXTNO,
            0x170000013 => Tag::MIPS_GOTSYM,
            0x170000014 => Tag::MIPS_HIPAGENO,
            0x170000016 => Tag::MIPS_RLD_MAP,
            0x170000017 => Tag::MIPS_DELTA_CLASS,
            0x170000018 => Tag::MIPS_DELTA_CLASS_NO,
            0x170000019 => Tag::MIPS_DELTA_INSTANCE,
            0x17000001a => Tag::MIPS_DELTA_INSTANCE_NO,
            0x17000001b => Tag::MIPS_DELTA_RELOC,
            0x17000001c => Tag::MIPS_DELTA_RELOC_NO,
            0x17000001d => Tag::MIPS_DELTA_SYM,
            0x17000001e => Tag::MIPS_DELTA_SYM_NO,
            0x170000020 => Tag::MIPS_DELTA_CLASSSYM,
            0x170000021 => Tag::MIPS_DELTA_CLASSSYM_NO,
            0x170000022 => Tag::MIPS_CXX_FLAGS,
            0x170000023 => Tag::MIPS_PIXIE_INIT,
            0x170000024 => Tag::MIPS_SYMBOL_LIB,
            0x170000025 => Tag::MIPS_LOCALPAGE_GOTIDX,
            0x170000026 => Tag::MIPS_LOCAL_GOTIDX,
            0x170000027 => Tag::MIPS_HIDDEN_GOTIDX,
            0x170000028 => Tag::MIPS_PROTECTED_GOTIDX,
            0x170000029 => Tag::MIPS_OPTIONS,
            0x17000002a => Tag::MIPS_INTERFACE,
            0x17000002b => Tag::MIPS_DYNSTR_ALIGN,
            0x17000002c => Tag::MIPS_INTERFACE_SIZE,
            0x17000002d => Tag::MIPS_RLD_TEXT_RESOLVE_ADDR,
            0x17000002e => Tag::MIPS_PERF_SUFFIX,
            0x17000002f => Tag::MIPS_COMPACT_SIZE,
            0x170000030 => Tag::MIPS_GP_VALUE,
            0x170000031 => Tag::MIPS_AUX_DYNAMIC,
            0x170000032 => Tag::MIPS_PLTGOT,
            0x170000034 => Tag::MIPS_RWPLT,
            0x170000035 => Tag::MIPS_RLD_MAP_REL,
            0x170000036 => Tag::MIPS_XHASH,
            0x270000001 => Tag::AARCH64_BTI_PLT,
            0x270000003 => Tag::AARCH64_PAC_PLT,
            0x270000005 => Tag::AARCH64_VARIANT_PCS,
            0x270000009 => Tag::AARCH64_MEMTAG_MODE,
            0x27000000b => Tag::AARCH64_MEMTAG_HEAP,
            0x27000000c => Tag::AARCH64_MEMTAG_STACK,
            0x27000000d => Tag::AARCH64_MEMTAG_GLOBALS,
            0x27000000f => Tag::AARCH64_MEMTAG_GLOBALSSZ,
            0x370000000 => Tag::HEXAGON_SYMSZ,
            0x370000001 => Tag::HEXAGON_VER,
            0x370000002 => Tag::HEXAGON_PLT,
            0x470000000 => Tag::PPC_GOT,
            0x470000001 => Tag::PPC_OPT,
            0x570000000 => Tag::PPC64_GLINK,
            0x570000003 => Tag::PPC64_OPT,
            0x670000003 => Tag::RISCV_VARIANT_CC,
            _ => Tag::UNKNOWN(value),

        }
    }
}
impl From<Tag> for u64 {
    fn from(value: Tag) -> u64 {
        match value {
            Tag::DT_NULL => 0x00000000,
            Tag::NEEDED => 0x00000001,
            Tag::PLTRELSZ => 0x00000002,
            Tag::PLTGOT => 0x00000003,
            Tag::HASH => 0x00000004,
            Tag::STRTAB => 0x00000005,
            Tag::SYMTAB => 0x00000006,
            Tag::RELA => 0x00000007,
            Tag::RELASZ => 0x00000008,
            Tag::RELAENT => 0x00000009,
            Tag::STRSZ => 0x0000000a,
            Tag::SYMENT => 0x0000000b,
            Tag::INIT => 0x0000000c,
            Tag::FINI => 0x0000000d,
            Tag::SONAME => 0x0000000e,
            Tag::RPATH => 0x0000000f,
            Tag::SYMBOLIC => 0x00000010,
            Tag::REL => 0x00000011,
            Tag::RELSZ => 0x00000012,
            Tag::RELENT => 0x00000013,
            Tag::PLTREL => 0x00000014,
            Tag::DEBUG_TAG => 0x00000015,
            Tag::TEXTREL => 0x00000016,
            Tag::JMPREL => 0x00000017,
            Tag::BIND_NOW => 0x00000018,
            Tag::INIT_ARRAY => 0x00000019,
            Tag::FINI_ARRAY => 0x0000001a,
            Tag::INIT_ARRAYSZ => 0x0000001b,
            Tag::FINI_ARRAYSZ => 0x0000001c,
            Tag::RUNPATH => 0x0000001d,
            Tag::FLAGS => 0x0000001e,
            Tag::PREINIT_ARRAY => 0x00000020,
            Tag::PREINIT_ARRAYSZ => 0x00000021,
            Tag::SYMTAB_SHNDX => 0x00000022,
            Tag::RELRSZ => 0x00000023,
            Tag::RELR => 0x00000024,
            Tag::RELRENT => 0x00000025,
            Tag::GNU_HASH => 0x6ffffef5,
            Tag::RELACOUNT => 0x6ffffff9,
            Tag::RELCOUNT => 0x6ffffffa,
            Tag::FLAGS_1 => 0x6ffffffb,
            Tag::VERSYM => 0x6ffffff0,
            Tag::VERDEF => 0x6ffffffc,
            Tag::VERDEFNUM => 0x6ffffffd,
            Tag::VERNEED => 0x6ffffffe,
            Tag::VERNEEDNUM => 0x6fffffff,
            Tag::ANDROID_REL_OFFSET => 0x6000000d,
            Tag::ANDROID_REL_SIZE => 0x6000000e,
            Tag::ANDROID_REL => 0x6000000f,
            Tag::ANDROID_RELSZ => 0x60000010,
            Tag::ANDROID_RELA => 0x60000011,
            Tag::ANDROID_RELASZ => 0x60000012,
            Tag::ANDROID_RELR => 0x6fffe000,
            Tag::ANDROID_RELRSZ => 0x6fffe001,
            Tag::ANDROID_RELRENT => 0x6fffe003,
            Tag::ANDROID_RELRCOUNT => 0x6fffe005,
            Tag::MIPS_RLD_VERSION => 0x170000001,
            Tag::MIPS_TIME_STAMP => 0x170000002,
            Tag::MIPS_ICHECKSUM => 0x170000003,
            Tag::MIPS_IVERSION => 0x170000004,
            Tag::MIPS_FLAGS => 0x170000005,
            Tag::MIPS_BASE_ADDRESS => 0x170000006,
            Tag::MIPS_MSYM => 0x170000007,
            Tag::MIPS_CONFLICT => 0x170000008,
            Tag::MIPS_LIBLIST => 0x170000009,
            Tag::MIPS_LOCAL_GOTNO => 0x17000000a,
            Tag::MIPS_CONFLICTNO => 0x17000000b,
            Tag::MIPS_LIBLISTNO => 0x170000010,
            Tag::MIPS_SYMTABNO => 0x170000011,
            Tag::MIPS_UNREFEXTNO => 0x170000012,
            Tag::MIPS_GOTSYM => 0x170000013,
            Tag::MIPS_HIPAGENO => 0x170000014,
            Tag::MIPS_RLD_MAP => 0x170000016,
            Tag::MIPS_DELTA_CLASS => 0x170000017,
            Tag::MIPS_DELTA_CLASS_NO => 0x170000018,
            Tag::MIPS_DELTA_INSTANCE => 0x170000019,
            Tag::MIPS_DELTA_INSTANCE_NO => 0x17000001a,
            Tag::MIPS_DELTA_RELOC => 0x17000001b,
            Tag::MIPS_DELTA_RELOC_NO => 0x17000001c,
            Tag::MIPS_DELTA_SYM => 0x17000001d,
            Tag::MIPS_DELTA_SYM_NO => 0x17000001e,
            Tag::MIPS_DELTA_CLASSSYM => 0x170000020,
            Tag::MIPS_DELTA_CLASSSYM_NO => 0x170000021,
            Tag::MIPS_CXX_FLAGS => 0x170000022,
            Tag::MIPS_PIXIE_INIT => 0x170000023,
            Tag::MIPS_SYMBOL_LIB => 0x170000024,
            Tag::MIPS_LOCALPAGE_GOTIDX => 0x170000025,
            Tag::MIPS_LOCAL_GOTIDX => 0x170000026,
            Tag::MIPS_HIDDEN_GOTIDX => 0x170000027,
            Tag::MIPS_PROTECTED_GOTIDX => 0x170000028,
            Tag::MIPS_OPTIONS => 0x170000029,
            Tag::MIPS_INTERFACE => 0x17000002a,
            Tag::MIPS_DYNSTR_ALIGN => 0x17000002b,
            Tag::MIPS_INTERFACE_SIZE => 0x17000002c,
            Tag::MIPS_RLD_TEXT_RESOLVE_ADDR => 0x17000002d,
            Tag::MIPS_PERF_SUFFIX => 0x17000002e,
            Tag::MIPS_COMPACT_SIZE => 0x17000002f,
            Tag::MIPS_GP_VALUE => 0x170000030,
            Tag::MIPS_AUX_DYNAMIC => 0x170000031,
            Tag::MIPS_PLTGOT => 0x170000032,
            Tag::MIPS_RWPLT => 0x170000034,
            Tag::MIPS_RLD_MAP_REL => 0x170000035,
            Tag::MIPS_XHASH => 0x170000036,
            Tag::AARCH64_BTI_PLT => 0x270000001,
            Tag::AARCH64_PAC_PLT => 0x270000003,
            Tag::AARCH64_VARIANT_PCS => 0x270000005,
            Tag::AARCH64_MEMTAG_MODE => 0x270000009,
            Tag::AARCH64_MEMTAG_HEAP => 0x27000000b,
            Tag::AARCH64_MEMTAG_STACK => 0x27000000c,
            Tag::AARCH64_MEMTAG_GLOBALS => 0x27000000d,
            Tag::AARCH64_MEMTAG_GLOBALSSZ => 0x27000000f,
            Tag::HEXAGON_SYMSZ => 0x370000000,
            Tag::HEXAGON_VER => 0x370000001,
            Tag::HEXAGON_PLT => 0x370000002,
            Tag::PPC_GOT => 0x470000000,
            Tag::PPC_OPT => 0x470000001,
            Tag::PPC64_GLINK => 0x570000000,
            Tag::PPC64_OPT => 0x570000003,
            Tag::RISCV_VARIANT_CC => 0x670000003,
            Tag::UNKNOWN(value) => value,
        }
    }
}


#[derive(Debug)]
/// Enum that represents the different variants of a dynamic entry
pub enum Entries<'a> {
    /// Entry for `DT_NEEDED`
    Library(Library<'a>),

    /// Entry for `DT_INIT_ARRAY, DT_FINI_ARRAY`, ...
    Array(Array<'a>),

    /// Entry for `DT_RPATH`
    Rpath(Rpath<'a>),

    /// Entry for `DT_RUNPATH`
    RunPath(RunPath<'a>),

    /// Entry for `DT_SONAME`
    SharedObject(SharedObject<'a>),

    /// Generic value
    Generic(Generic<'a>),
}

/// Trait shared by all the [`Entries`]
pub trait DynamicEntry {
    #[doc(hidden)]
    fn as_base(&self) -> &ffi::ELF_DynamicEntry;

    /// Dynamic TAG associated with the entry
    fn tag(&self) -> Tag {
        Tag::from(self.as_base().tag())
    }

    /// Raw value which should be interpreted according to the [`DynamicEntry::tag`]
    fn value(&self) -> u64 {
        self.as_base().value()
    }
}

impl DynamicEntry for Entries<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        match &self {
            Entries::Library(entry) => {
                entry.as_base()
            }

            Entries::Array(entry) => {
                entry.as_base()
            }

            Entries::Rpath(entry) => {
                entry.as_base()
            }

            Entries::RunPath(entry) => {
                entry.as_base()
            }

            Entries::SharedObject(entry) => {
                entry.as_base()
            }

            Entries::Generic(entry) => {
                entry.as_base()
            }
        }
    }

}

impl FromFFI<ffi::ELF_DynamicEntry> for Entries<'_> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::ELF_DynamicEntry>) -> Self {
        unsafe {
            let cmd_ref = ffi_entry.as_ref().unwrap();

            if ffi::ELF_DynamicEntryLibrary::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_DynamicEntry>;
                    type To   = cxx::UniquePtr<ffi::ELF_DynamicEntryLibrary>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::Library(Library::from_ffi(raw))
            }
            else if ffi::ELF_DynamicEntryArray::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_DynamicEntry>;
                    type To   = cxx::UniquePtr<ffi::ELF_DynamicEntryArray>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::Array(Array::from_ffi(raw))
            }
            else if ffi::ELF_DynamicEntryRpath::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_DynamicEntry>;
                    type To   = cxx::UniquePtr<ffi::ELF_DynamicEntryRpath>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::Rpath(Rpath::from_ffi(raw))
            }
            else if ffi::ELF_DynamicEntryRunPath::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_DynamicEntry>;
                    type To   = cxx::UniquePtr<ffi::ELF_DynamicEntryRunPath>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::RunPath(RunPath::from_ffi(raw))
            }
            else if ffi::ELF_DynamicSharedObject::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_DynamicEntry>;
                    type To   = cxx::UniquePtr<ffi::ELF_DynamicSharedObject>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::SharedObject(SharedObject::from_ffi(raw))
            }
            else {
                Entries::Generic(Generic::from_ffi(ffi_entry))
            }
        }
    }
}


/// Generic structure for the dynamic entries whose [`DynamicEntry::value`] can be interpreted
/// as is.
pub struct Generic<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_DynamicEntry>,
    _owner: PhantomData<&'a ffi::ELF_Binary>
}

impl FromFFI<ffi::ELF_DynamicEntry> for Generic<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_DynamicEntry>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }

}

impl DynamicEntry for Generic<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap()
    }
}

impl std::fmt::Debug for Generic<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Generic").finish()
    }
}

/// Structure that represents a dynamic entry associated with a library name (e.g. `DT_NEEDED`)
pub struct Library<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryLibrary>,
    _owner: PhantomData<&'a ffi::ELF_Binary>
}

impl Library<'_> {
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }
}

impl FromFFI<ffi::ELF_DynamicEntryLibrary> for Library<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryLibrary>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}


impl DynamicEntry for Library<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for Library<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Library").finish()
    }
}

/// Structure that represents a dynamic entry associated with an array (e.g. `DT_INIT_ARRAY`)
pub struct Array<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryArray>,
    _owner: PhantomData<&'a ffi::ELF_Binary>
}

impl Array<'_> {
    pub fn array(&self) -> Vec<u64> {
        Vec::from(self.ptr.array().as_slice())
    }
}

impl FromFFI<ffi::ELF_DynamicEntryArray> for Array<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryArray>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

impl DynamicEntry for Array<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for Array<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Array").finish()
    }
}

/// Structure that represents a dynamic entry associated with the rpath info
pub struct Rpath<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryRpath>,
    _owner: PhantomData<&'a ffi::ELF_Binary>
}

impl Rpath<'_> {
    pub fn rpath(&self) -> String {
        self.ptr.rpath().to_string()
    }
}

impl FromFFI<ffi::ELF_DynamicEntryRpath> for Rpath<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryRpath>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}


impl DynamicEntry for Rpath<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for Rpath<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rpath").finish()
    }
}

/// Structure that represents a dynamic entry associated with the runpath info
pub struct RunPath<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryRunPath>,
    _owner: PhantomData<&'a ffi::ELF_Binary>
}

impl RunPath<'_> {
    pub fn runpath(&self) -> String {
        self.ptr.runpath().to_string()
    }
}

impl FromFFI<ffi::ELF_DynamicEntryRunPath> for RunPath<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryRunPath>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}


impl DynamicEntry for RunPath<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for RunPath<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunPath").finish()
    }
}

/// Structure that represents a dynamic entry associated with the name of a library (`DT_SONAME`)
pub struct SharedObject<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_DynamicSharedObject>,
    _owner: PhantomData<&'a ffi::ELF_Binary>
}

impl SharedObject<'_> {
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }
}

impl FromFFI<ffi::ELF_DynamicSharedObject> for SharedObject<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_DynamicSharedObject>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}


impl DynamicEntry for SharedObject<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for SharedObject<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedObject").finish()
    }
}

declare_iterator!(DynamicEntries, Entries<'a>, ffi::ELF_DynamicEntry, ffi::ELF_Binary, ffi::ELF_Binary_it_dynamic_entries);
