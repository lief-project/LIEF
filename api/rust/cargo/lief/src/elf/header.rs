use lief_ffi as ffi;

use std::{fmt, marker::PhantomData};

use crate::common::FromFFI;


#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// The type of the underlying ELF file. This enum matches
/// the semantic of `ET_NONE`, `ET_REL`, ...
pub enum FileType {
    /// Can't be determined
    NONE,

    /// Relocatable file (or object file)
    REL,

    /// non-pie executable
    EXEC,

    /// Shared library **or** a pie-executable
    DYN,

    /// Core dump file
    CORE,
    UNKNOWN(u32),
}


impl FileType {
    pub fn from_value(value: u32) -> Self {
        match value {
            0x00000000 => FileType::NONE,
            0x00000001 => FileType::REL,
            0x00000002 => FileType::EXEC,
            0x00000003 => FileType::DYN,
            0x00000004 => FileType::CORE,
            _ => FileType::UNKNOWN(value),

        }
    }
}


#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Match the result of `Elfxx_Ehdr.e_version`
pub enum Version {
    /// Invalid ELF version
    NONE,

    /// Current version (default)
    CURRENT,
    UNKNOWN(u32),
}

impl Version {
    pub fn from_value(value: u32) -> Self {
        match value {
            0x00000000 => Version::NONE,
            0x00000001 => Version::CURRENT,
            _ => Version::UNKNOWN(value),

        }
    }
}


#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Match the result of `Elfxx_Ehdr.e_ident[EI_CLASS]`
pub enum Class {
    /// Invalid class
    NONE,

    /// 32-bit objects
    ELF32,

    /// 64-bits objects
    ELF64,
    UNKNOWN(u32),
}

impl Class {
    pub fn from_value(value: u32) -> Self {
        match value {
            0x00000000 => Class::NONE,
            0x00000001 => Class::ELF32,
            0x00000002 => Class::ELF64,
            _ => Class::UNKNOWN(value),

        }
    }
}


#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Match the result `Elfxx_Ehdr.e_ident[EI_OSABI]`
pub enum OsAbi {
    /// UNIX System V ABI
    SYSTEMV,
    /// HP-UX operating system
    HPUX,
    /// NetBSD
    NETBSD,
    /// GNU/Linux
    GNU,
    /// Historical alias for ELFOSABI_GNU.
    LINUX,
    /// GNU/Hurd
    HURD,
    /// Solaris
    SOLARIS,
    /// AIX
    AIX,
    /// IRIX
    IRIX,
    /// FreeBSD
    FREEBSD,
    /// TRU64 UNIX
    TRU64,
    /// Novell Modesto
    MODESTO,
    /// OpenBSD
    OPENBSD,
    /// OpenVMS
    OPENVMS,
    /// Hewlett-Packard Non-Stop Kernel
    NSK,
    /// AROS
    AROS,
    /// FenixOS
    FENIXOS,
    /// Nuxi CloudABI
    CLOUDABI,
    /// Bare-metal TMS320C6000
    C6000_ELFABI,
    /// AMD HSA runtim
    AMDGPU_HSA,
    /// Linux TMS320C6000
    C6000_LINUX,
    /// ARM
    ARM,
    /// Standalone (embedded) applicatio
    STANDALONE,
    UNKNOWN(u32),
}


impl OsAbi {
    pub fn from_value(value: u32) -> Self {
        match value {
            0x00000000 => OsAbi::SYSTEMV,
            0x00000001 => OsAbi::HPUX,
            0x00000002 => OsAbi::NETBSD,
            0x00000003 => OsAbi::LINUX,
            0x00000004 => OsAbi::HURD,
            0x00000006 => OsAbi::SOLARIS,
            0x00000007 => OsAbi::AIX,
            0x00000008 => OsAbi::IRIX,
            0x00000009 => OsAbi::FREEBSD,
            0x0000000a => OsAbi::TRU64,
            0x0000000b => OsAbi::MODESTO,
            0x0000000c => OsAbi::OPENBSD,
            0x0000000d => OsAbi::OPENVMS,
            0x0000000e => OsAbi::NSK,
            0x0000000f => OsAbi::AROS,
            0x00000010 => OsAbi::FENIXOS,
            0x00000011 => OsAbi::CLOUDABI,
            /* 0x00000040 => OsAbi::C6000_ELFABI, */
            0x00000040 => OsAbi::AMDGPU_HSA,
            0x00000041 => OsAbi::C6000_LINUX,
            0x00000061 => OsAbi::ARM,
            0x000000ff => OsAbi::STANDALONE,
            _ => OsAbi::UNKNOWN(value),

        }
    }
}


#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Match the result `Elfxx_Ehdr.e_ident[EI_DATA]`
pub enum ElfData {
    /// Invalid data encodin
    NONE,
    /// 2's complement, little endian
    LSB,
    /// 2's complement, big endian
    MSB,
    UNKNOWN(u32),
}

impl ElfData {
    pub fn from_value(value: u32) -> Self {
        match value {
            0x00000000 => ElfData::NONE,
            0x00000001 => ElfData::LSB,
            0x00000002 => ElfData::MSB,
            _ => ElfData::UNKNOWN(value),

        }
    }
}

/// Class which represents the ELF's header. This class mirrors the raw
/// ELF `Elfxx_Ehdr` structure
pub struct Header<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_Header>,
    _owner: PhantomData<&'a ffi::ELF_Binary>
}

impl FromFFI<ffi::ELF_Header> for Header<'_> {
    fn from_ffi(hdr: cxx::UniquePtr<ffi::ELF_Header>) -> Self {
        Self {
            ptr: hdr,
            _owner: PhantomData
        }
    }
}

impl Header<'_> {
    /// Executable entrypoint
    pub fn entrypoint(&self) -> u64 {
        self.ptr.entrypoint()
    }

    /// Define the object file type. (e.g. executable, library...)
    pub fn file_type(&self) -> FileType {
        FileType::from_value(self.ptr.file_type())
    }

    /// Version of the object file format
    pub fn object_file_version(&self) -> Version {
        Version::from_value(self.ptr.object_file_version())
    }

    /// Return the object's class. `ELF64` or `ELF32`
    pub fn identity_class(&self) -> Class {
        Class::from_value(self.ptr.identity_class())
    }

    /// Specify the data encoding
    pub fn identity_data(&self) -> ElfData {
        ElfData::from_value(self.ptr.identity_data())
    }

    /// See: [`Header::object_file_version`]
    pub fn identity_version(&self) -> Version {
        Version::from_value(self.ptr.identity_version())
    }

    /// Identifies the version of the ABI for which the object is prepared
    pub fn identity_os_abi(&self) -> OsAbi {
        OsAbi::from_value(self.ptr.identity_os_abi())
    }

    /// Target architecture
    pub fn machine_type(&self) -> u32 {
        self.ptr.machine_type()
    }

    /// Offset of the programs table (also known as segments table)
    pub fn program_headers_offset(&self) -> u64 {
        self.ptr.program_headers_offset()
    }

    /// Offset of the sections table
    pub fn section_headers_offset(&self) -> u64 {
        self.ptr.section_headers_offset()
    }

    /// Processor-specific flags
    pub fn processor_flag(&self) -> u32 {
        self.ptr.processor_flag()
    }

    /// Size of the current header (i.e. `sizeof(Elfxx_Ehdr)`)
    /// This size should be 64 for an `ELF64` binary and 52 for an `ELF32`.
    pub fn header_size(&self) -> u32 {
        self.ptr.header_size()
    }

    /// Return the size of a program header (i.e. `sizeof(Elfxx_Phdr)`)
    /// This size should be 56 for an `ELF64` binary and 32 for an `ELF32`.
    pub fn program_header_size(&self) -> u32 {
        self.ptr.program_header_size()
    }

    /// Return the the number of segments
    pub fn numberof_segments(&self) -> u32 {
        self.ptr.numberof_segments()
    }

    /// Return the size of a section header (i.e. `sizeof(Elfxx_Shdr)`)
    /// This size should be 64 for a ``ELF64`` binary and 40 for an ``ELF32``.
    pub fn section_header_size(&self) -> u32 {
        self.ptr.section_header_size()
    }

    /// Return the number of sections
    ///
    /// <div class="warning">
    /// This value could differ from the real number of sections
    /// present in the binary. It must be taken as an <i>indication</i>
    /// </div>
    pub fn numberof_sections(&self) -> u32 {
        self.ptr.numberof_sections()
    }

    /// Return the section's index which contains sections' names
    pub fn section_name_table_idx(&self) -> u32 {
        self.ptr.section_name_table_idx()
    }
}

impl fmt::Debug for Header<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field("entrypoint", &self.entrypoint())
            .field("object_file_version", &self.object_file_version())
            .field("identity_class", &self.identity_class())
            .field("identity_os_abi", &self.identity_os_abi())
            .field("identity_data", &self.identity_data())
            .field("identity_version", &self.identity_version())
            .field("file_type", &self.file_type())
            .field("machine_type", &self.machine_type())
            .field("program_headers_offset", &self.program_headers_offset())
            .field("section_headers_offset", &self.section_headers_offset())
            .field("processor_flag", &self.processor_flag())
            .field("header_size", &self.header_size())
            .field("program_header_size", &self.program_header_size())
            .field("numberof_segments", &self.numberof_segments())
            .field("section_header_size", &self.section_header_size())
            .field("numberof_sections", &self.numberof_sections())
            .field("section_name_table_idx", &self.section_name_table_idx())
            .finish()
    }
}
