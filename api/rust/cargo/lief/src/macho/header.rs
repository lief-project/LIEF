use lief_ffi as ffi;

use bitflags::bitflags;

use std::{fmt, marker::PhantomData};
use crate::common::FromFFI;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum FileType {
    OBJECT,
    EXECUTE,
    FVMLIB,
    CORE,
    PRELOAD,
    DYLIB,
    DYLINKER,
    BUNDLE,
    DYLIB_STUB,
    DSYM,
    KEXT_BUNDLE,
    UNKNOWN(u32),
}

impl From<u32> for FileType {
    fn from(value: u32) -> Self {
        match value {
            0x00000001 => FileType::OBJECT,
            0x00000002 => FileType::EXECUTE,
            0x00000003 => FileType::FVMLIB,
            0x00000004 => FileType::CORE,
            0x00000005 => FileType::PRELOAD,
            0x00000006 => FileType::DYLIB,
            0x00000007 => FileType::DYLINKER,
            0x00000008 => FileType::BUNDLE,
            0x00000009 => FileType::DYLIB_STUB,
            0x0000000a => FileType::DSYM,
            0x0000000b => FileType::KEXT_BUNDLE,
            _ => FileType::UNKNOWN(value),

        }
    }
}
impl From<FileType> for u32 {
    fn from(value: FileType) -> u32 {
        match value {
            FileType::OBJECT => 0x00000001,
            FileType::EXECUTE => 0x00000002,
            FileType::FVMLIB => 0x00000003,
            FileType::CORE => 0x00000004,
            FileType::PRELOAD => 0x00000005,
            FileType::DYLIB => 0x00000006,
            FileType::DYLINKER => 0x00000007,
            FileType::BUNDLE => 0x00000008,
            FileType::DYLIB_STUB => 0x00000009,
            FileType::DSYM => 0x0000000a,
            FileType::KEXT_BUNDLE => 0x0000000b,
            FileType::UNKNOWN(_) => 0xFF,
        }
    }
}


#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum CpuType {
    ANY,
    X86,
    X86_64,
    MIPS,
    MC98000,
    ARM,
    ARM64,
    SPARC,
    POWERPC,
    POWERPC64,
    UNKNOWN(i32),
}

impl From<i32> for CpuType {
    fn from(value: i32) -> Self {
        match value {
            -1 => CpuType::ANY,
            0x00000007 => CpuType::X86,
            0x01000007 => CpuType::X86_64,
            0x00000008 => CpuType::MIPS,
            0x0000000a => CpuType::MC98000,
            0x0000000c => CpuType::ARM,
            0x0100000c => CpuType::ARM64,
            0x0000000e => CpuType::SPARC,
            0x00000012 => CpuType::POWERPC,
            0x01000012 => CpuType::POWERPC64,
            _ => CpuType::UNKNOWN(value),

        }
    }
}
impl From<CpuType> for i32 {
    fn from(value: CpuType) -> i32 {
        match value {
            CpuType::ANY => -1,
            CpuType::X86 => 0x00000007,
            CpuType::X86_64 => 0x01000007,
            CpuType::MIPS => 0x00000008,
            CpuType::MC98000 => 0x0000000a,
            CpuType::ARM => 0x0000000c,
            CpuType::ARM64 => 0x0100000c,
            CpuType::SPARC => 0x0000000e,
            CpuType::POWERPC => 0x00000012,
            CpuType::POWERPC64 => 0x01000012,
            CpuType::UNKNOWN(_) => -1,

        }
    }
}


bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Flags: u32 {
        const NOUNDEFS = 0x1;
        const INCRLINK = 0x2;
        const DYLDLINK = 0x4;
        const BINDATLOAD = 0x8;
        const PREBOUND = 0x10;
        const SPLIT_SEGS = 0x20;
        const LAZY_INIT = 0x40;
        const TWOLEVEL = 0x80;
        const FORCE_FLAT = 0x100;
        const NOMULTIDEFS = 0x200;
        const NOFIXPREBINDING = 0x400;
        const PREBINDABLE = 0x800;
        const ALLMODSBOUND = 0x1000;
        const SUBSECTIONS_VIA_SYMBOLS = 0x2000;
        const CANONICAL = 0x4000;
        const WEAK_DEFINES = 0x8000;
        const BINDS_TO_WEAK = 0x10000;
        const ALLOW_STACK_EXECUTION = 0x20000;
        const ROOT_SAFE = 0x40000;
        const SETUID_SAFE = 0x80000;
        const NO_REEXPORTED_DYLIBS = 0x100000;
        const PIE = 0x200000;
        const DEAD_STRIPPABLE_DYLIB = 0x400000;
        const HAS_TLV_DESCRIPTORS = 0x800000;
        const NO_HEAP_EXECUTION = 0x1000000;
        const APP_EXTENSION_SAFE = 0x2000000;
    }
}


impl From<u32> for Flags {
    fn from(value: u32) -> Self {
        Flags::from_bits_truncate(value)
    }
}
impl From<Flags> for u32 {
    fn from(value: Flags) -> Self {
        value.bits()
    }
}

/// Structure that represents the main Mach-O header (at the beginning of the file)
pub struct Header<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_Header>,
    _owner: PhantomData<&'a ffi::MachO_Binary>
}

impl FromFFI<ffi::MachO_Header> for Header<'_> {
    fn from_ffi(hdr: cxx::UniquePtr<ffi::MachO_Header>) -> Self {
        Self {
            ptr: hdr,
            _owner: PhantomData
        }
    }
}

impl Header<'_> {
    /// The Mach-O magic bytes. These bytes determine whether it is
    /// a 32 bits Mach-O, a 64 bits Mach-O files etc.
    pub fn magic(&self) -> u32 {
        self.ptr.magic()
    }

    /// The CPU architecture targeted by this binary
    pub fn cpu_type(&self) -> CpuType {
        CpuType::from(self.ptr.cpu_type())
    }

    /// Return the CPU subtype supported by the Mach-O binary.
    /// For ARM architectures, this value could represent the minimum version
    /// for which the Mach-O binary has been compiled for.
    pub fn cpu_subtype(&self) -> u32 {
        self.ptr.cpu_subtype()
    }

    /// Return the type of the Mach-O file (executable, object, shared library, ...)
    pub fn file_type(&self) -> FileType {
        FileType::from(self.ptr.file_type())
    }

    /// Number of [`crate::macho::Commands`] present in the Mach-O binary
    pub fn nb_cmds(&self) -> u32 {
        self.ptr.nb_cmds()
    }

    /// The raw size of **all** the load commands (`LC_xxx`)
    pub fn sizeof_cmds(&self) -> u32 {
        self.ptr.sizeof_cmds()
    }

    /// Header flags
    pub fn flags(&self) -> Flags {
        Flags::from(self.ptr.flags())
    }

    /// According to the official specs, a reserved value
    pub fn reserved(&self) -> u32 {
        self.ptr.reserved()
    }
}

impl fmt::Debug for Header<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field("magic", &self.magic())
            .field("cpu_type", &self.cpu_type())
            .field("cpu_subtype", &self.cpu_subtype())
            .field("file_type", &self.file_type())
            .field("nb_cmds", &self.nb_cmds())
            .field("sizeof_cmds", &self.sizeof_cmds())
            .field("flags", &self.flags())
            .field("reserved", &self.reserved())
            .finish()
    }
}
