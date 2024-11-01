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
    pub fn machine_type(&self) -> Arch {
        Arch::from(self.ptr.machine_type())
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

    /// Return the number of segments
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

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Arch {
    NONE,
    M32,
    SPARC,
    I386,
    M68K,
    M88K,
    IAMCU,
    I860,
    MIPS,
    S370,
    MIPS_RS3_LE,
    PARISC,
    VPP500,
    SPARC32PLUS,
    I60,
    PPC,
    PPC64,
    S390,
    SPU,
    V800,
    FR20,
    RH32,
    RCE,
    ARM,
    ALPHA,
    SH,
    SPARCV9,
    TRICORE,
    ARC,
    H8_300,
    H8_300H,
    H8S,
    H8_500,
    IA_64,
    MIPS_X,
    COLDFIRE,
    M68HC12,
    MMA,
    PCP,
    NCPU,
    NDR1,
    STARCORE,
    ME16,
    ST100,
    TINYJ,
    X86_64,
    PDSP,
    PDP10,
    PDP11,
    FX66,
    ST9PLUS,
    ST7,
    M68HC16,
    M68HC11,
    M68HC08,
    M68HC05,
    SVX,
    ST19,
    VAX,
    CRIS,
    JAVELIN,
    FIREPATH,
    ZSP,
    MMIX,
    HUANY,
    PRISM,
    AVR,
    FR30,
    D10V,
    D30V,
    V850,
    M32R,
    MN10300,
    MN10200,
    PJ,
    OPENRISC,
    ARC_COMPACT,
    XTENSA,
    VIDEOCORE,
    TMM_GPP,
    NS32K,
    TPC,
    SNP1K,
    ST200,
    IP2K,
    MAX,
    CR,
    F2MC16,
    MSP430,
    BLACKFIN,
    SE_C33,
    SEP,
    ARCA,
    UNICORE,
    EXCESS,
    DXP,
    ALTERA_NIOS2,
    CRX,
    XGATE,
    C166,
    M16C,
    DSPIC30F,
    CE,
    M32C,
    TSK3000,
    RS08,
    SHARC,
    ECOG2,
    SCORE7,
    DSP24,
    VIDEOCORE3,
    LATTICEMICO32,
    SE_C17,
    TI_C6000,
    TI_C2000,
    TI_C5500,
    MMDSP_PLUS,
    CYPRESS_M8C,
    R32C,
    TRIMEDIA,
    HEXAGON,
    M8051,
    STXP7X,
    NDS32,
    ECOG1,
    //ECOG1X,
    MAXQ30,
    XIMO16,
    MANIK,
    CRAYNV2,
    RX,
    METAG,
    MCST_ELBRUS,
    ECOG16,
    CR16,
    ETPU,
    SLE9X,
    L10M,
    K10M,
    AARCH64,
    AVR32,
    STM8,
    TILE64,
    TILEPRO,
    CUDA,
    TILEGX,
    CLOUDSHIELD,
    COREA_1ST,
    COREA_2ND,
    ARC_COMPACT2,
    OPEN8,
    RL78,
    VIDEOCORE5,
    M78KOR,
    M56800EX,
    BA1,
    BA2,
    XCORE,
    MCHP_PIC,
    INTEL205,
    INTEL206,
    INTEL207,
    INTEL208,
    INTEL209,
    KM32,
    KMX32,
    KMX16,
    KMX8,
    KVARC,
    CDP,
    COGE,
    COOL,
    NORC,
    CSR_KALIMBA,
    AMDGPU,
    RISCV,
    BPF,
    CSKY,
    LOONGARCH,
    UNKNOWN(u32),
}

impl From<u32> for Arch {
    fn from(value: u32) -> Self {
        match value {
            0x00000000 => Arch::NONE,
            0x00000001 => Arch::M32,
            0x00000002 => Arch::SPARC,
            0x00000003 => Arch::I386,
            0x00000004 => Arch::M68K,
            0x00000005 => Arch::M88K,
            0x00000006 => Arch::IAMCU,
            0x00000007 => Arch::I860,
            0x00000008 => Arch::MIPS,
            0x00000009 => Arch::S370,
            0x0000000a => Arch::MIPS_RS3_LE,
            0x0000000f => Arch::PARISC,
            0x00000011 => Arch::VPP500,
            0x00000012 => Arch::SPARC32PLUS,
            0x00000013 => Arch::I60,
            0x00000014 => Arch::PPC,
            0x00000015 => Arch::PPC64,
            0x00000016 => Arch::S390,
            0x00000017 => Arch::SPU,
            0x00000024 => Arch::V800,
            0x00000025 => Arch::FR20,
            0x00000026 => Arch::RH32,
            0x00000027 => Arch::RCE,
            0x00000028 => Arch::ARM,
            0x00000029 => Arch::ALPHA,
            0x0000002a => Arch::SH,
            0x0000002b => Arch::SPARCV9,
            0x0000002c => Arch::TRICORE,
            0x0000002d => Arch::ARC,
            0x0000002e => Arch::H8_300,
            0x0000002f => Arch::H8_300H,
            0x00000030 => Arch::H8S,
            0x00000031 => Arch::H8_500,
            0x00000032 => Arch::IA_64,
            0x00000033 => Arch::MIPS_X,
            0x00000034 => Arch::COLDFIRE,
            0x00000035 => Arch::M68HC12,
            0x00000036 => Arch::MMA,
            0x00000037 => Arch::PCP,
            0x00000038 => Arch::NCPU,
            0x00000039 => Arch::NDR1,
            0x0000003a => Arch::STARCORE,
            0x0000003b => Arch::ME16,
            0x0000003c => Arch::ST100,
            0x0000003d => Arch::TINYJ,
            0x0000003e => Arch::X86_64,
            0x0000003f => Arch::PDSP,
            0x00000040 => Arch::PDP10,
            0x00000041 => Arch::PDP11,
            0x00000042 => Arch::FX66,
            0x00000043 => Arch::ST9PLUS,
            0x00000044 => Arch::ST7,
            0x00000045 => Arch::M68HC16,
            0x00000046 => Arch::M68HC11,
            0x00000047 => Arch::M68HC08,
            0x00000048 => Arch::M68HC05,
            0x00000049 => Arch::SVX,
            0x0000004a => Arch::ST19,
            0x0000004b => Arch::VAX,
            0x0000004c => Arch::CRIS,
            0x0000004d => Arch::JAVELIN,
            0x0000004e => Arch::FIREPATH,
            0x0000004f => Arch::ZSP,
            0x00000050 => Arch::MMIX,
            0x00000051 => Arch::HUANY,
            0x00000052 => Arch::PRISM,
            0x00000053 => Arch::AVR,
            0x00000054 => Arch::FR30,
            0x00000055 => Arch::D10V,
            0x00000056 => Arch::D30V,
            0x00000057 => Arch::V850,
            0x00000058 => Arch::M32R,
            0x00000059 => Arch::MN10300,
            0x0000005a => Arch::MN10200,
            0x0000005b => Arch::PJ,
            0x0000005c => Arch::OPENRISC,
            0x0000005d => Arch::ARC_COMPACT,
            0x0000005e => Arch::XTENSA,
            0x0000005f => Arch::VIDEOCORE,
            0x00000060 => Arch::TMM_GPP,
            0x00000061 => Arch::NS32K,
            0x00000062 => Arch::TPC,
            0x00000063 => Arch::SNP1K,
            0x00000064 => Arch::ST200,
            0x00000065 => Arch::IP2K,
            0x00000066 => Arch::MAX,
            0x00000067 => Arch::CR,
            0x00000068 => Arch::F2MC16,
            0x00000069 => Arch::MSP430,
            0x0000006a => Arch::BLACKFIN,
            0x0000006b => Arch::SE_C33,
            0x0000006c => Arch::SEP,
            0x0000006d => Arch::ARCA,
            0x0000006e => Arch::UNICORE,
            0x0000006f => Arch::EXCESS,
            0x00000070 => Arch::DXP,
            0x00000071 => Arch::ALTERA_NIOS2,
            0x00000072 => Arch::CRX,
            0x00000073 => Arch::XGATE,
            0x00000074 => Arch::C166,
            0x00000075 => Arch::M16C,
            0x00000076 => Arch::DSPIC30F,
            0x00000077 => Arch::CE,
            0x00000078 => Arch::M32C,
            0x00000083 => Arch::TSK3000,
            0x00000084 => Arch::RS08,
            0x00000085 => Arch::SHARC,
            0x00000086 => Arch::ECOG2,
            0x00000087 => Arch::SCORE7,
            0x00000088 => Arch::DSP24,
            0x00000089 => Arch::VIDEOCORE3,
            0x0000008a => Arch::LATTICEMICO32,
            0x0000008b => Arch::SE_C17,
            0x0000008c => Arch::TI_C6000,
            0x0000008d => Arch::TI_C2000,
            0x0000008e => Arch::TI_C5500,
            0x000000a0 => Arch::MMDSP_PLUS,
            0x000000a1 => Arch::CYPRESS_M8C,
            0x000000a2 => Arch::R32C,
            0x000000a3 => Arch::TRIMEDIA,
            0x000000a4 => Arch::HEXAGON,
            0x000000a5 => Arch::M8051,
            0x000000a6 => Arch::STXP7X,
            0x000000a7 => Arch::NDS32,
            0x000000a8 => Arch::ECOG1,
            /*0x000000a8 => Arch::ECOG1X,*/
            0x000000a9 => Arch::MAXQ30,
            0x000000aa => Arch::XIMO16,
            0x000000ab => Arch::MANIK,
            0x000000ac => Arch::CRAYNV2,
            0x000000ad => Arch::RX,
            0x000000ae => Arch::METAG,
            0x000000af => Arch::MCST_ELBRUS,
            0x000000b0 => Arch::ECOG16,
            0x000000b1 => Arch::CR16,
            0x000000b2 => Arch::ETPU,
            0x000000b3 => Arch::SLE9X,
            0x000000b4 => Arch::L10M,
            0x000000b5 => Arch::K10M,
            0x000000b7 => Arch::AARCH64,
            0x000000b9 => Arch::AVR32,
            0x000000ba => Arch::STM8,
            0x000000bb => Arch::TILE64,
            0x000000bc => Arch::TILEPRO,
            0x000000be => Arch::CUDA,
            0x000000bf => Arch::TILEGX,
            0x000000c0 => Arch::CLOUDSHIELD,
            0x000000c1 => Arch::COREA_1ST,
            0x000000c2 => Arch::COREA_2ND,
            0x000000c3 => Arch::ARC_COMPACT2,
            0x000000c4 => Arch::OPEN8,
            0x000000c5 => Arch::RL78,
            0x000000c6 => Arch::VIDEOCORE5,
            0x000000c7 => Arch::M78KOR,
            0x000000c8 => Arch::M56800EX,
            0x000000c9 => Arch::BA1,
            0x000000ca => Arch::BA2,
            0x000000cb => Arch::XCORE,
            0x000000cc => Arch::MCHP_PIC,
            0x000000cd => Arch::INTEL205,
            0x000000ce => Arch::INTEL206,
            0x000000cf => Arch::INTEL207,
            0x000000d0 => Arch::INTEL208,
            0x000000d1 => Arch::INTEL209,
            0x000000d2 => Arch::KM32,
            0x000000d3 => Arch::KMX32,
            0x000000d4 => Arch::KMX16,
            0x000000d5 => Arch::KMX8,
            0x000000d6 => Arch::KVARC,
            0x000000d7 => Arch::CDP,
            0x000000d8 => Arch::COGE,
            0x000000d9 => Arch::COOL,
            0x000000da => Arch::NORC,
            0x000000db => Arch::CSR_KALIMBA,
            0x000000e0 => Arch::AMDGPU,
            0x000000f3 => Arch::RISCV,
            0x000000f7 => Arch::BPF,
            0x000000fc => Arch::CSKY,
            0x00000102 => Arch::LOONGARCH,
            _ => Arch::UNKNOWN(value),

        }
    }
}
impl From<Arch> for u32 {
    fn from(value: Arch) -> u32 {
        match value {
            Arch::NONE => 0x00000000,
            Arch::M32 => 0x00000001,
            Arch::SPARC => 0x00000002,
            Arch::I386 => 0x00000003,
            Arch::M68K => 0x00000004,
            Arch::M88K => 0x00000005,
            Arch::IAMCU => 0x00000006,
            Arch::I860 => 0x00000007,
            Arch::MIPS => 0x00000008,
            Arch::S370 => 0x00000009,
            Arch::MIPS_RS3_LE => 0x0000000a,
            Arch::PARISC => 0x0000000f,
            Arch::VPP500 => 0x00000011,
            Arch::SPARC32PLUS => 0x00000012,
            Arch::I60 => 0x00000013,
            Arch::PPC => 0x00000014,
            Arch::PPC64 => 0x00000015,
            Arch::S390 => 0x00000016,
            Arch::SPU => 0x00000017,
            Arch::V800 => 0x00000024,
            Arch::FR20 => 0x00000025,
            Arch::RH32 => 0x00000026,
            Arch::RCE => 0x00000027,
            Arch::ARM => 0x00000028,
            Arch::ALPHA => 0x00000029,
            Arch::SH => 0x0000002a,
            Arch::SPARCV9 => 0x0000002b,
            Arch::TRICORE => 0x0000002c,
            Arch::ARC => 0x0000002d,
            Arch::H8_300 => 0x0000002e,
            Arch::H8_300H => 0x0000002f,
            Arch::H8S => 0x00000030,
            Arch::H8_500 => 0x00000031,
            Arch::IA_64 => 0x00000032,
            Arch::MIPS_X => 0x00000033,
            Arch::COLDFIRE => 0x00000034,
            Arch::M68HC12 => 0x00000035,
            Arch::MMA => 0x00000036,
            Arch::PCP => 0x00000037,
            Arch::NCPU => 0x00000038,
            Arch::NDR1 => 0x00000039,
            Arch::STARCORE => 0x0000003a,
            Arch::ME16 => 0x0000003b,
            Arch::ST100 => 0x0000003c,
            Arch::TINYJ => 0x0000003d,
            Arch::X86_64 => 0x0000003e,
            Arch::PDSP => 0x0000003f,
            Arch::PDP10 => 0x00000040,
            Arch::PDP11 => 0x00000041,
            Arch::FX66 => 0x00000042,
            Arch::ST9PLUS => 0x00000043,
            Arch::ST7 => 0x00000044,
            Arch::M68HC16 => 0x00000045,
            Arch::M68HC11 => 0x00000046,
            Arch::M68HC08 => 0x00000047,
            Arch::M68HC05 => 0x00000048,
            Arch::SVX => 0x00000049,
            Arch::ST19 => 0x0000004a,
            Arch::VAX => 0x0000004b,
            Arch::CRIS => 0x0000004c,
            Arch::JAVELIN => 0x0000004d,
            Arch::FIREPATH => 0x0000004e,
            Arch::ZSP => 0x0000004f,
            Arch::MMIX => 0x00000050,
            Arch::HUANY => 0x00000051,
            Arch::PRISM => 0x00000052,
            Arch::AVR => 0x00000053,
            Arch::FR30 => 0x00000054,
            Arch::D10V => 0x00000055,
            Arch::D30V => 0x00000056,
            Arch::V850 => 0x00000057,
            Arch::M32R => 0x00000058,
            Arch::MN10300 => 0x00000059,
            Arch::MN10200 => 0x0000005a,
            Arch::PJ => 0x0000005b,
            Arch::OPENRISC => 0x0000005c,
            Arch::ARC_COMPACT => 0x0000005d,
            Arch::XTENSA => 0x0000005e,
            Arch::VIDEOCORE => 0x0000005f,
            Arch::TMM_GPP => 0x00000060,
            Arch::NS32K => 0x00000061,
            Arch::TPC => 0x00000062,
            Arch::SNP1K => 0x00000063,
            Arch::ST200 => 0x00000064,
            Arch::IP2K => 0x00000065,
            Arch::MAX => 0x00000066,
            Arch::CR => 0x00000067,
            Arch::F2MC16 => 0x00000068,
            Arch::MSP430 => 0x00000069,
            Arch::BLACKFIN => 0x0000006a,
            Arch::SE_C33 => 0x0000006b,
            Arch::SEP => 0x0000006c,
            Arch::ARCA => 0x0000006d,
            Arch::UNICORE => 0x0000006e,
            Arch::EXCESS => 0x0000006f,
            Arch::DXP => 0x00000070,
            Arch::ALTERA_NIOS2 => 0x00000071,
            Arch::CRX => 0x00000072,
            Arch::XGATE => 0x00000073,
            Arch::C166 => 0x00000074,
            Arch::M16C => 0x00000075,
            Arch::DSPIC30F => 0x00000076,
            Arch::CE => 0x00000077,
            Arch::M32C => 0x00000078,
            Arch::TSK3000 => 0x00000083,
            Arch::RS08 => 0x00000084,
            Arch::SHARC => 0x00000085,
            Arch::ECOG2 => 0x00000086,
            Arch::SCORE7 => 0x00000087,
            Arch::DSP24 => 0x00000088,
            Arch::VIDEOCORE3 => 0x00000089,
            Arch::LATTICEMICO32 => 0x0000008a,
            Arch::SE_C17 => 0x0000008b,
            Arch::TI_C6000 => 0x0000008c,
            Arch::TI_C2000 => 0x0000008d,
            Arch::TI_C5500 => 0x0000008e,
            Arch::MMDSP_PLUS => 0x000000a0,
            Arch::CYPRESS_M8C => 0x000000a1,
            Arch::R32C => 0x000000a2,
            Arch::TRIMEDIA => 0x000000a3,
            Arch::HEXAGON => 0x000000a4,
            Arch::M8051 => 0x000000a5,
            Arch::STXP7X => 0x000000a6,
            Arch::NDS32 => 0x000000a7,
            Arch::ECOG1 => 0x000000a8,
            /*Arch::ECOG1X => 0x000000a8,*/
            Arch::MAXQ30 => 0x000000a9,
            Arch::XIMO16 => 0x000000aa,
            Arch::MANIK => 0x000000ab,
            Arch::CRAYNV2 => 0x000000ac,
            Arch::RX => 0x000000ad,
            Arch::METAG => 0x000000ae,
            Arch::MCST_ELBRUS => 0x000000af,
            Arch::ECOG16 => 0x000000b0,
            Arch::CR16 => 0x000000b1,
            Arch::ETPU => 0x000000b2,
            Arch::SLE9X => 0x000000b3,
            Arch::L10M => 0x000000b4,
            Arch::K10M => 0x000000b5,
            Arch::AARCH64 => 0x000000b7,
            Arch::AVR32 => 0x000000b9,
            Arch::STM8 => 0x000000ba,
            Arch::TILE64 => 0x000000bb,
            Arch::TILEPRO => 0x000000bc,
            Arch::CUDA => 0x000000be,
            Arch::TILEGX => 0x000000bf,
            Arch::CLOUDSHIELD => 0x000000c0,
            Arch::COREA_1ST => 0x000000c1,
            Arch::COREA_2ND => 0x000000c2,
            Arch::ARC_COMPACT2 => 0x000000c3,
            Arch::OPEN8 => 0x000000c4,
            Arch::RL78 => 0x000000c5,
            Arch::VIDEOCORE5 => 0x000000c6,
            Arch::M78KOR => 0x000000c7,
            Arch::M56800EX => 0x000000c8,
            Arch::BA1 => 0x000000c9,
            Arch::BA2 => 0x000000ca,
            Arch::XCORE => 0x000000cb,
            Arch::MCHP_PIC => 0x000000cc,
            Arch::INTEL205 => 0x000000cd,
            Arch::INTEL206 => 0x000000ce,
            Arch::INTEL207 => 0x000000cf,
            Arch::INTEL208 => 0x000000d0,
            Arch::INTEL209 => 0x000000d1,
            Arch::KM32 => 0x000000d2,
            Arch::KMX32 => 0x000000d3,
            Arch::KMX16 => 0x000000d4,
            Arch::KMX8 => 0x000000d5,
            Arch::KVARC => 0x000000d6,
            Arch::CDP => 0x000000d7,
            Arch::COGE => 0x000000d8,
            Arch::COOL => 0x000000d9,
            Arch::NORC => 0x000000da,
            Arch::CSR_KALIMBA => 0x000000db,
            Arch::AMDGPU => 0x000000e0,
            Arch::RISCV => 0x000000f3,
            Arch::BPF => 0x000000f7,
            Arch::CSKY => 0x000000fc,
            Arch::LOONGARCH => 0x00000102,
            Arch::UNKNOWN(value) => value,

        }
    }
}
