use lief_ffi as ffi;

use std::{fmt, marker::PhantomData};

use crate::common::FromFFI;


#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FileType {
    NONE,
    REL,
    EXEC,
    DYN,
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
pub enum Version {
    NONE,
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
pub enum Class {
    NONE,
    ELF32,
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
pub enum OsAbi {
    SYSTEMV,
    HPUX,
    NETBSD,
    GNU,
    LINUX,
    HURD,
    SOLARIS,
    AIX,
    IRIX,
    FREEBSD,
    TRU64,
    MODESTO,
    OPENBSD,
    OPENVMS,
    NSK,
    AROS,
    FENIXOS,
    CLOUDABI,
    C6000_ELFABI,
    AMDGPU_HSA,
    C6000_LINUX,
    ARM,
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
pub enum ElfData {
    NONE,
    LSB,
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
    pub fn entrypoint(&self) -> u64 {
        self.ptr.entrypoint()
    }
    pub fn file_type(&self) -> FileType {
        FileType::from_value(self.ptr.file_type())
    }
    pub fn object_file_version(&self) -> Version {
        Version::from_value(self.ptr.object_file_version())
    }
    pub fn identity_class(&self) -> Class {
        Class::from_value(self.ptr.identity_class())
    }
    pub fn identity_data(&self) -> ElfData {
        ElfData::from_value(self.ptr.identity_data())
    }
    pub fn identity_version(&self) -> Version {
        Version::from_value(self.ptr.identity_version())
    }
    pub fn identity_os_abi(&self) -> OsAbi {
        OsAbi::from_value(self.ptr.identity_os_abi())
    }
    pub fn machine_type(&self) -> u32 {
        self.ptr.machine_type()
    }
    pub fn program_headers_offset(&self) -> u64 {
        self.ptr.program_headers_offset()
    }
    pub fn section_headers_offset(&self) -> u64 {
        self.ptr.section_headers_offset()
    }
    pub fn processor_flag(&self) -> u32 {
        self.ptr.processor_flag()
    }
    pub fn header_size(&self) -> u32 {
        self.ptr.header_size()
    }
    pub fn program_header_size(&self) -> u32 {
        self.ptr.program_header_size()
    }
    pub fn numberof_segments(&self) -> u32 {
        self.ptr.numberof_segments()
    }
    pub fn section_header_size(&self) -> u32 {
        self.ptr.section_header_size()
    }
    pub fn numberof_sections(&self) -> u32 {
        self.ptr.numberof_sections()
    }
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
