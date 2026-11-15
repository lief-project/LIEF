use std::marker::PhantomData;

use bitflags::bitflags;
use lief_ffi as ffi;
use std::pin::Pin;

use crate::common::FromFFI;
use crate::{declare_iterator, enum_from_int};

enum_from_int! {
    #[allow(non_camel_case_types)]
    Tag: u64 {
        DT_NULL_ = 0x00000000,
        NEEDED = 0x00000001,
        PLTRELSZ = 0x00000002,
        PLTGOT = 0x00000003,
        HASH = 0x00000004,
        STRTAB = 0x00000005,
        SYMTAB = 0x00000006,
        RELA = 0x00000007,
        RELASZ = 0x00000008,
        RELAENT = 0x00000009,
        STRSZ = 0x0000000a,
        SYMENT = 0x0000000b,
        INIT = 0x0000000c,
        FINI = 0x0000000d,
        SONAME = 0x0000000e,
        RPATH = 0x0000000f,
        SYMBOLIC = 0x00000010,
        REL = 0x00000011,
        RELSZ = 0x00000012,
        RELENT = 0x00000013,
        PLTREL = 0x00000014,
        DEBUG_TAG = 0x00000015,
        TEXTREL = 0x00000016,
        JMPREL = 0x00000017,
        BIND_NOW = 0x00000018,
        INIT_ARRAY = 0x00000019,
        FINI_ARRAY = 0x0000001a,
        INIT_ARRAYSZ = 0x0000001b,
        FINI_ARRAYSZ = 0x0000001c,
        RUNPATH = 0x0000001d,
        FLAGS = 0x0000001e,
        PREINIT_ARRAY = 0x00000020,
        PREINIT_ARRAYSZ = 0x00000021,
        SYMTAB_SHNDX = 0x00000022,
        RELRSZ = 0x00000023,
        RELR = 0x00000024,
        RELRENT = 0x00000025,
        GNU_HASH = 0x6ffffef5,
        TLSDESC_PLT = 0x6ffffef6,
        TLSDESC_GOT = 0x6ffffef7,
        RELACOUNT = 0x6ffffff9,
        RELCOUNT = 0x6ffffffa,
        FLAGS_1 = 0x6ffffffb,
        VERSYM = 0x6ffffff0,
        VERDEF = 0x6ffffffc,
        VERDEFNUM = 0x6ffffffd,
        VERNEED = 0x6ffffffe,
        VERNEEDNUM = 0x6fffffff,
        AUXILIARY = 0x7ffffffd,
        FILTER = 0x7fffffff,
        ANDROID_REL_OFFSET = 0x6000000d,
        ANDROID_REL_SIZE = 0x6000000e,
        ANDROID_REL = 0x6000000f,
        ANDROID_RELSZ = 0x60000010,
        ANDROID_RELA = 0x60000011,
        ANDROID_RELASZ = 0x60000012,
        ANDROID_RELR = 0x6fffe000,
        ANDROID_RELRSZ = 0x6fffe001,
        ANDROID_RELRENT = 0x6fffe003,
        ANDROID_RELRCOUNT = 0x6fffe005,
        MIPS_RLD_VERSION = 0x170000001,
        MIPS_TIME_STAMP = 0x170000002,
        MIPS_ICHECKSUM = 0x170000003,
        MIPS_IVERSION = 0x170000004,
        MIPS_FLAGS = 0x170000005,
        MIPS_BASE_ADDRESS = 0x170000006,
        MIPS_MSYM = 0x170000007,
        MIPS_CONFLICT = 0x170000008,
        MIPS_LIBLIST = 0x170000009,
        MIPS_LOCAL_GOTNO = 0x17000000a,
        MIPS_CONFLICTNO = 0x17000000b,
        MIPS_LIBLISTNO = 0x170000010,
        MIPS_SYMTABNO = 0x170000011,
        MIPS_UNREFEXTNO = 0x170000012,
        MIPS_GOTSYM = 0x170000013,
        MIPS_HIPAGENO = 0x170000014,
        MIPS_RLD_MAP = 0x170000016,
        MIPS_DELTA_CLASS = 0x170000017,
        MIPS_DELTA_CLASS_NO = 0x170000018,
        MIPS_DELTA_INSTANCE = 0x170000019,
        MIPS_DELTA_INSTANCE_NO = 0x17000001a,
        MIPS_DELTA_RELOC = 0x17000001b,
        MIPS_DELTA_RELOC_NO = 0x17000001c,
        MIPS_DELTA_SYM = 0x17000001d,
        MIPS_DELTA_SYM_NO = 0x17000001e,
        MIPS_DELTA_CLASSSYM = 0x170000020,
        MIPS_DELTA_CLASSSYM_NO = 0x170000021,
        MIPS_CXX_FLAGS = 0x170000022,
        MIPS_PIXIE_INIT = 0x170000023,
        MIPS_SYMBOL_LIB = 0x170000024,
        MIPS_LOCALPAGE_GOTIDX = 0x170000025,
        MIPS_LOCAL_GOTIDX = 0x170000026,
        MIPS_HIDDEN_GOTIDX = 0x170000027,
        MIPS_PROTECTED_GOTIDX = 0x170000028,
        MIPS_OPTIONS = 0x170000029,
        MIPS_INTERFACE = 0x17000002a,
        MIPS_DYNSTR_ALIGN = 0x17000002b,
        MIPS_INTERFACE_SIZE = 0x17000002c,
        MIPS_RLD_TEXT_RESOLVE_ADDR = 0x17000002d,
        MIPS_PERF_SUFFIX = 0x17000002e,
        MIPS_COMPACT_SIZE = 0x17000002f,
        MIPS_GP_VALUE = 0x170000030,
        MIPS_AUX_DYNAMIC = 0x170000031,
        MIPS_PLTGOT = 0x170000032,
        MIPS_RWPLT = 0x170000034,
        MIPS_RLD_MAP_REL = 0x170000035,
        MIPS_XHASH = 0x170000036,
        AARCH64_BTI_PLT = 0x270000001,
        AARCH64_PAC_PLT = 0x270000003,
        AARCH64_VARIANT_PCS = 0x270000005,
        AARCH64_MEMTAG_MODE = 0x270000009,
        AARCH64_MEMTAG_HEAP = 0x27000000b,
        AARCH64_MEMTAG_STACK = 0x27000000c,
        AARCH64_MEMTAG_GLOBALS = 0x27000000d,
        AARCH64_MEMTAG_GLOBALSSZ = 0x27000000f,
        HEXAGON_SYMSZ = 0x370000000,
        HEXAGON_VER = 0x370000001,
        HEXAGON_PLT = 0x370000002,
        PPC_GOT = 0x470000000,
        PPC_OPT = 0x470000001,
        PPC64_GLINK = 0x570000000,
        PPC64_OPT = 0x570000003,
        RISCV_VARIANT_CC = 0x670000003,
        X86_64_PLT = 0x770000000,
        X86_64_PLTSZ = 0x770000001,
        X86_64_PLTENT = 0x770000003,
        IA_64_PLT_RESERVE = 0x870000000,
        IA_64_VMS_SUBTYPE = 0x860000000,
        IA_64_VMS_IMGIOCNT = 0x860000002,
        IA_64_VMS_LNKFLAGS = 0x860000008,
        IA_64_VMS_VIR_MEM_BLK_SIZ = 0x86000000a,
        IA_64_VMS_IDENT = 0x86000000c,
        IA_64_VMS_NEEDED_IDENT = 0x860000010,
        IA_64_VMS_IMG_RELA_CNT = 0x860000012,
        IA_64_VMS_SEG_RELA_CNT = 0x860000014,
        IA_64_VMS_FIXUP_RELA_CNT = 0x860000016,
        IA_64_VMS_FIXUP_NEEDED = 0x860000018,
        IA_64_VMS_SYMVEC_CNT = 0x86000001a,
        IA_64_VMS_XLATED = 0x86000001e,
        IA_64_VMS_STACKSIZE = 0x860000020,
        IA_64_VMS_UNWINDSZ = 0x860000022,
        IA_64_VMS_UNWIND_CODSEG = 0x860000024,
        IA_64_VMS_UNWIND_INFOSEG = 0x860000026,
        IA_64_VMS_LINKTIME = 0x860000028,
        IA_64_VMS_SEG_NO = 0x86000002a,
        IA_64_VMS_SYMVEC_OFFSET = 0x86000002c,
        IA_64_VMS_SYMVEC_SEG = 0x86000002e,
        IA_64_VMS_UNWIND_OFFSET = 0x860000030,
        IA_64_VMS_UNWIND_SEG = 0x860000032,
        IA_64_VMS_STRTAB_OFFSET = 0x860000034,
        IA_64_VMS_SYSVER_OFFSET = 0x860000036,
        IA_64_VMS_IMG_RELA_OFF = 0x860000038,
        IA_64_VMS_SEG_RELA_OFF = 0x86000003a,
        IA_64_VMS_FIXUP_RELA_OFF = 0x86000003c,
        IA_64_VMS_PLTGOT_OFFSET = 0x86000003e,
        IA_64_VMS_PLTGOT_SEG = 0x860000040,
        IA_64_VMS_FPMODE = 0x860000042,
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

    /// Entry for `DT_AUXILIARY`
    Auxiliary(Auxiliary<'a>),

    /// Entry for `DT_FILTER`
    Filter(Filter<'a>),

    /// Entry for `DT_FLAGS` and `DT_FLAGS_1`
    Flags(Flags<'a>),

    /// Generic value
    Generic(Generic<'a>),
}

impl Entries<'_> {
    /// Create a new dynamic entry with the given Tag
    pub fn with_tag(tag: Tag) -> Entries<'static> {
        Entries::from_ffi(lief_ffi::ELF_DynamicEntry::create(tag.into()))
    }
}

/// Trait shared by all the [`Entries`]
pub trait DynamicEntry {
    #[doc(hidden)]
    fn as_base(&self) -> &ffi::ELF_DynamicEntry;

    #[doc(hidden)]
    fn as_mut_base(&mut self) -> Pin<&mut ffi::ELF_DynamicEntry>;

    /// Dynamic TAG associated with the entry
    fn tag(&self) -> Tag {
        Tag::from(self.as_base().tag())
    }

    /// Raw value which should be interpreted according to the [`DynamicEntry::tag`]
    fn value(&self) -> u64 {
        self.as_base().value()
    }

    fn set_value(&mut self, value: u64) {
        self.as_mut_base().set_value(value);
    }
}

impl std::fmt::Display for &dyn DynamicEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_base().to_string())
    }
}

impl DynamicEntry for Entries<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        match &self {
            Entries::Library(entry) => entry.as_base(),

            Entries::Array(entry) => entry.as_base(),

            Entries::Rpath(entry) => entry.as_base(),

            Entries::RunPath(entry) => entry.as_base(),

            Entries::SharedObject(entry) => entry.as_base(),

            Entries::Auxiliary(entry) => entry.as_base(),

            Entries::Filter(entry) => entry.as_base(),

            Entries::Flags(entry) => entry.as_base(),

            Entries::Generic(entry) => entry.as_base(),
        }
    }

    fn as_mut_base(&mut self) -> Pin<&mut ffi::ELF_DynamicEntry> {
        match self {
            Entries::Library(entry) => entry.as_mut_base(),

            Entries::Array(entry) => entry.as_mut_base(),

            Entries::Rpath(entry) => entry.as_mut_base(),

            Entries::RunPath(entry) => entry.as_mut_base(),

            Entries::SharedObject(entry) => entry.as_mut_base(),

            Entries::Auxiliary(entry) => entry.as_mut_base(),

            Entries::Filter(entry) => entry.as_mut_base(),

            Entries::Flags(entry) => entry.as_mut_base(),

            Entries::Generic(entry) => entry.as_mut_base(),
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
                    type To = cxx::UniquePtr<ffi::ELF_DynamicEntryLibrary>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::Library(Library::from_ffi(raw))
            } else if ffi::ELF_DynamicEntryArray::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_DynamicEntry>;
                    type To = cxx::UniquePtr<ffi::ELF_DynamicEntryArray>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::Array(Array::from_ffi(raw))
            } else if ffi::ELF_DynamicEntryRpath::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_DynamicEntry>;
                    type To = cxx::UniquePtr<ffi::ELF_DynamicEntryRpath>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::Rpath(Rpath::from_ffi(raw))
            } else if ffi::ELF_DynamicEntryRunPath::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_DynamicEntry>;
                    type To = cxx::UniquePtr<ffi::ELF_DynamicEntryRunPath>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::RunPath(RunPath::from_ffi(raw))
            } else if ffi::ELF_DynamicSharedObject::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_DynamicEntry>;
                    type To = cxx::UniquePtr<ffi::ELF_DynamicSharedObject>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::SharedObject(SharedObject::from_ffi(raw))
            } else if ffi::ELF_DynamicEntryAuxiliary::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_DynamicEntry>;
                    type To = cxx::UniquePtr<ffi::ELF_DynamicEntryAuxiliary>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::Auxiliary(Auxiliary::from_ffi(raw))
            } else if ffi::ELF_DynamicEntryFilter::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_DynamicEntry>;
                    type To = cxx::UniquePtr<ffi::ELF_DynamicEntryFilter>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::Filter(Filter::from_ffi(raw))
            } else if ffi::ELF_DynamicEntryFlags::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_DynamicEntry>;
                    type To = cxx::UniquePtr<ffi::ELF_DynamicEntryFlags>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::Flags(Flags::from_ffi(raw))
            } else {
                Entries::Generic(Generic::from_ffi(ffi_entry))
            }
        }
    }
}

/// Generic structure for the dynamic entries whose [`DynamicEntry::value`] can be interpreted
/// as is.
pub struct Generic<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_DynamicEntry>,
    _owner: PhantomData<&'a ffi::ELF_Binary>,
}

impl FromFFI<ffi::ELF_DynamicEntry> for Generic<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_DynamicEntry>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DynamicEntry for Generic<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap()
    }

    fn as_mut_base(&mut self) -> Pin<&mut ffi::ELF_DynamicEntry> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap() as *const ffi::ELF_DynamicEntry
                    as *mut ffi::ELF_DynamicEntry)
                    .as_mut()
                    .unwrap()
            })
        }
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
    _owner: PhantomData<&'a ffi::ELF_Binary>,
}

impl Library<'_> {
    /// Name of the library (e.g. `libc.so.6`)
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// Set a new library name
    pub fn set_name(&mut self, new_name: &str) {
        cxx::let_cxx_string!(__cxx_s = new_name.to_string());
        self.ptr.pin_mut().set_name(&__cxx_s);
    }
}

impl FromFFI<ffi::ELF_DynamicEntryLibrary> for Library<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryLibrary>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DynamicEntry for Library<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap().as_ref()
    }

    fn as_mut_base(&mut self) -> Pin<&mut ffi::ELF_DynamicEntry> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref() as *const ffi::ELF_DynamicEntry
                    as *mut ffi::ELF_DynamicEntry)
                    .as_mut()
                    .unwrap()
            })
        }
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
    _owner: PhantomData<&'a ffi::ELF_Binary>,
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
            _owner: PhantomData,
        }
    }
}

impl DynamicEntry for Array<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap().as_ref()
    }

    fn as_mut_base(&mut self) -> Pin<&mut ffi::ELF_DynamicEntry> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref() as *const ffi::ELF_DynamicEntry
                    as *mut ffi::ELF_DynamicEntry)
                    .as_mut()
                    .unwrap()
            })
        }
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
    _owner: PhantomData<&'a ffi::ELF_Binary>,
}

impl Rpath<'_> {
    /// Create a new Rpath entry with the given path(s)
    ///
    /// For instance:
    ///
    /// ```
    /// Rpath::new("$ORIGIN/../:/lib64")
    /// ```
    pub fn new(value: &str) -> Rpath<'static> {
        cxx::let_cxx_string!(__cxx_s = value.to_string());
        Rpath::from_ffi(lief_ffi::ELF_DynamicEntryRpath::create(&__cxx_s))
    }

    /// Create a new Rpath entry from a slice of paths
    ///
    /// For instance:
    ///
    /// ```
    /// Rpath::with_paths(&vec!["$ORIGIN/../", "/lib64"])
    /// ```
    pub fn with_paths(values: &[&str]) -> Rpath<'static> {
        Rpath::new(&values.join(":"))
    }

    /// The actual rpath as a string
    pub fn rpath(&self) -> String {
        self.ptr.rpath().to_string()
    }

    /// Change the rpath value
    pub fn set_rpath(&mut self, value: &str) {
        cxx::let_cxx_string!(__cxx_s = value.to_string());
        self.ptr.pin_mut().set_rpath(&__cxx_s);
    }

    /// Change the rpath value with the given slice
    pub fn set_rpath_with_value(&mut self, values: &[&str]) {
        cxx::let_cxx_string!(__cxx_s = values.join(":"));
        self.ptr.pin_mut().set_rpath(&__cxx_s);
    }

    /// The specified paths as a list of string
    pub fn paths(&self) -> Vec<String> {
        let mut result = Vec::new();
        for entry in self.ptr.paths().into_iter() {
            result.push(entry.to_string());
        }
        result
    }

    /// Insert a `path` at the given `position`
    pub fn insert(&mut self, pos: u32, path: &str) {
        cxx::let_cxx_string!(__cxx_s = path.to_string());
        self.ptr.pin_mut().insert(pos, &__cxx_s);
    }

    /// Append the given path
    pub fn append(&mut self, path: &str) {
        cxx::let_cxx_string!(__cxx_s = path.to_string());
        self.ptr.pin_mut().append(&__cxx_s);
    }

    /// The given path
    pub fn remove(&mut self, path: &str) {
        cxx::let_cxx_string!(__cxx_s = path.to_string());
        self.ptr.pin_mut().remove(&__cxx_s);
    }
}

impl FromFFI<ffi::ELF_DynamicEntryRpath> for Rpath<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryRpath>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DynamicEntry for Rpath<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap().as_ref()
    }

    fn as_mut_base(&mut self) -> Pin<&mut ffi::ELF_DynamicEntry> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref() as *const ffi::ELF_DynamicEntry
                    as *mut ffi::ELF_DynamicEntry)
                    .as_mut()
                    .unwrap()
            })
        }
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
    _owner: PhantomData<&'a ffi::ELF_Binary>,
}

impl RunPath<'_> {
    /// Create a new RunPath entry with the given path(s)
    ///
    /// For instance:
    ///
    /// ```
    /// RunPath::new("$ORIGIN/../:/lib64")
    /// ```
    pub fn new(value: &str) -> RunPath<'static> {
        cxx::let_cxx_string!(__cxx_s = value.to_string());
        RunPath::from_ffi(lief_ffi::ELF_DynamicEntryRunPath::create(&__cxx_s))
    }

    /// Create a new RunPath entry from a slice of paths
    ///
    /// For instance:
    ///
    /// ```
    /// RunPath::with_paths(&vec!["$ORIGIN/../", "/lib64"])
    /// ```
    pub fn with_paths(values: &[&str]) -> RunPath<'static> {
        RunPath::new(&values.join(":"))
    }

    pub fn runpath(&self) -> String {
        self.ptr.runpath().to_string()
    }

    /// The specified paths as a list of string
    pub fn paths(&self) -> Vec<String> {
        let mut result = Vec::new();
        for entry in self.ptr.paths().into_iter() {
            result.push(entry.to_string());
        }
        result
    }

    /// Change the runpath value
    pub fn set_runpath(&mut self, value: &str) {
        cxx::let_cxx_string!(__cxx_s = value.to_string());
        self.ptr.pin_mut().set_runpath(&__cxx_s);
    }

    /// Change the runpath value with the given slice
    pub fn set_runpath_with_value(&mut self, values: &[&str]) {
        cxx::let_cxx_string!(__cxx_s = values.join(":"));
        self.ptr.pin_mut().set_runpath(&__cxx_s);
    }

    /// Insert a `path` at the given `position`
    pub fn insert(&mut self, pos: u32, path: &str) {
        cxx::let_cxx_string!(__cxx_s = path.to_string());
        self.ptr.pin_mut().insert(pos, &__cxx_s);
    }

    /// Append the given path
    pub fn append(&mut self, path: &str) {
        cxx::let_cxx_string!(__cxx_s = path.to_string());
        self.ptr.pin_mut().append(&__cxx_s);
    }

    /// The given path
    pub fn remove(&mut self, path: &str) {
        cxx::let_cxx_string!(__cxx_s = path.to_string());
        self.ptr.pin_mut().remove(&__cxx_s);
    }
}

impl FromFFI<ffi::ELF_DynamicEntryRunPath> for RunPath<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryRunPath>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DynamicEntry for RunPath<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap().as_ref()
    }

    fn as_mut_base(&mut self) -> Pin<&mut ffi::ELF_DynamicEntry> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref() as *const ffi::ELF_DynamicEntry
                    as *mut ffi::ELF_DynamicEntry)
                    .as_mut()
                    .unwrap()
            })
        }
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
    _owner: PhantomData<&'a ffi::ELF_Binary>,
}

impl SharedObject<'_> {
    pub fn new(name: &str) -> SharedObject<'static> {
        cxx::let_cxx_string!(__cxx_s = name.to_string());
        SharedObject::from_ffi(lief_ffi::ELF_DynamicSharedObject::create(&__cxx_s))
    }

    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    pub fn set_name(&mut self, name: &str) {
        cxx::let_cxx_string!(__cxx_s = name.to_string());
        self.ptr.pin_mut().set_name(&__cxx_s);
    }
}

impl FromFFI<ffi::ELF_DynamicSharedObject> for SharedObject<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_DynamicSharedObject>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DynamicEntry for SharedObject<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap().as_ref()
    }

    fn as_mut_base(&mut self) -> Pin<&mut ffi::ELF_DynamicEntry> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref() as *const ffi::ELF_DynamicEntry
                    as *mut ffi::ELF_DynamicEntry)
                    .as_mut()
                    .unwrap()
            })
        }
    }
}

impl std::fmt::Debug for SharedObject<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedObject").finish()
    }
}

/// Structure that represents a dynamic entry associated with the name of a library (`DT_AUXILIARY`)
pub struct Auxiliary<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryAuxiliary>,
    _owner: PhantomData<&'a ffi::ELF_Binary>,
}

impl Auxiliary<'_> {
    pub fn new(name: &str) -> Auxiliary<'static> {
        cxx::let_cxx_string!(__cxx_s = name);
        Auxiliary::from_ffi(lief_ffi::ELF_DynamicEntryAuxiliary::create(&__cxx_s))
    }

    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    pub fn set_name(&mut self, name: &str) {
        cxx::let_cxx_string!(__cxx_s = name.to_string());
        self.ptr.pin_mut().set_name(&__cxx_s);
    }
}

impl FromFFI<ffi::ELF_DynamicEntryAuxiliary> for Auxiliary<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryAuxiliary>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DynamicEntry for Auxiliary<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap().as_ref()
    }

    fn as_mut_base(&mut self) -> Pin<&mut ffi::ELF_DynamicEntry> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref() as *const ffi::ELF_DynamicEntry
                    as *mut ffi::ELF_DynamicEntry)
                    .as_mut()
                    .unwrap()
            })
        }
    }
}

impl std::fmt::Debug for Auxiliary<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Auxiliary").finish()
    }
}

/// Structure that represents a dynamic entry associated with the name of a library (`DT_FILTER`)
pub struct Filter<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryFilter>,
    _owner: PhantomData<&'a ffi::ELF_Binary>,
}

impl Filter<'_> {
    pub fn new(name: &str) -> Filter<'static> {
        cxx::let_cxx_string!(__cxx_s = name.to_string());
        Filter::from_ffi(lief_ffi::ELF_DynamicEntryFilter::create(&__cxx_s))
    }

    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    pub fn set_name(&mut self, name: &str) {
        cxx::let_cxx_string!(__cxx_s = name.to_string());
        self.ptr.pin_mut().set_name(&__cxx_s);
    }
}

impl FromFFI<ffi::ELF_DynamicEntryFilter> for Filter<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryFilter>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DynamicEntry for Filter<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap().as_ref()
    }

    fn as_mut_base(&mut self) -> Pin<&mut ffi::ELF_DynamicEntry> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref() as *const ffi::ELF_DynamicEntry
                    as *mut ffi::ELF_DynamicEntry)
                    .as_mut()
                    .unwrap()
            })
        }
    }
}

impl std::fmt::Debug for Filter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Filter").finish()
    }
}

/// Structure that represents a dynamic flag entry: `DT_FLAGS` or `DT_FLAGS_1`
pub struct Flags<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryFlags>,
    _owner: PhantomData<&'a ffi::ELF_Binary>,
}

impl Flags<'_> {
    pub fn flags(&self) -> DtFlags {
        DtFlags::from(self.ptr.flags())
    }

    pub fn add_flag(&mut self, flag: DtFlags) {
        self.ptr.pin_mut().add_flag(flag.into())
    }

    pub fn remove_flag(&mut self, flag: DtFlags) {
        self.ptr.pin_mut().remove_flag(flag.into())
    }

    pub fn create_dt_flag(value: u64) -> Self {
        Self::from_ffi(ffi::ELF_DynamicEntryFlags::create_dt_flag(value))
    }

    pub fn create_dt_flag_1(value: u64) -> Self {
        Self::from_ffi(ffi::ELF_DynamicEntryFlags::create_dt_flag_1(value))
    }
}

impl FromFFI<ffi::ELF_DynamicEntryFlags> for Flags<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_DynamicEntryFlags>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DynamicEntry for Flags<'_> {
    fn as_base(&self) -> &ffi::ELF_DynamicEntry {
        self.ptr.as_ref().unwrap().as_ref()
    }

    fn as_mut_base(&mut self) -> Pin<&mut ffi::ELF_DynamicEntry> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref() as *const ffi::ELF_DynamicEntry
                    as *mut ffi::ELF_DynamicEntry)
                    .as_mut()
                    .unwrap()
            })
        }
    }
}

impl std::fmt::Debug for Flags<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Flags").finish()
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct DtFlags: u64 {
        const ORIGIN = 0x1;
        const SYMBOLIC = 0x2;
        const TEXTREL = 0x4;
        const BIND_NOW = 0x8;
        const STATIC_TLS = 0x10;
        const NOW = 0x100000001;
        const GLOBAL = 0x100000002;
        const GROUP = 0x100000004;
        const NODELETE = 0x100000008;
        const LOADFLTR = 0x100000010;
        const INITFIRST = 0x100000020;
        const NOOPEN = 0x100000040;
        const HANDLE_ORIGIN = 0x100000080;
        const DIRECT = 0x100000100;
        const TRANS = 0x100000200;
        const INTERPOSE = 0x100000400;
        const NODEFLIB = 0x100000800;
        const NODUMP = 0x100001000;
        const CONFALT = 0x100002000;
        const ENDFILTEE = 0x100004000;
        const DISPRELDNE = 0x100008000;
        const DISPRELPND = 0x100010000;
        const NODIRECT = 0x100020000;
        const IGNMULDEF = 0x100040000;
        const NOKSYMS = 0x100080000;
        const NOHDR = 0x100100000;
        const EDITED = 0x100200000;
        const NORELOC = 0x100400000;
        const SYMINTPOSE = 0x100800000;
        const GLOBAUDIT = 0x101000000;
        const SINGLETON = 0x102000000;
        const PIE = 0x108000000;
        const KMOD = 0x110000000;
        const WEAKFILTER = 0x120000000;
        const NOCOMMON = 0x140000000;
    }
}

impl From<u64> for DtFlags {
    fn from(value: u64) -> Self {
        DtFlags::from_bits_truncate(value)
    }
}
impl From<DtFlags> for u64 {
    fn from(value: DtFlags) -> Self {
        value.bits()
    }
}
impl std::fmt::Display for DtFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

declare_iterator!(
    DynamicEntries,
    Entries<'a>,
    ffi::ELF_DynamicEntry,
    ffi::ELF_Binary,
    ffi::ELF_Binary_it_dynamic_entries
);
