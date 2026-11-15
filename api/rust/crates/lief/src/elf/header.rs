use lief_ffi as ffi;

use std::{fmt, marker::PhantomData};

use crate::common::FromFFI;
use crate::{enum_from_int, to_slice};

enum_from_int! {
    #[allow(non_camel_case_types)]
    #[derive(PartialOrd, Ord)]
    /// The type of the underlying ELF file. This enum matches
    /// the semantic of `ET_NONE`, `ET_REL`, ...
    FileType: u32 {
        /// Can't be determined
        NONE = 0x00000000,

        /// Relocatable file (or object file)
        REL = 0x00000001,

        /// non-pie executable
        EXEC = 0x00000002,

        /// Shared library **or** a pie-executable
        DYN = 0x00000003,

        /// Core dump file
        CORE = 0x00000004,
    }
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    #[derive(PartialOrd, Ord)]
    /// Match the result of `Elfxx_Ehdr.e_version`
    Version: u32 {
        /// Invalid ELF version
        NONE = 0x00000000,

        /// Current version (default)
        CURRENT = 0x00000001,
    }
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    #[derive(PartialOrd, Ord)]
    /// Match the result of `Elfxx_Ehdr.e_ident[EI_CLASS]`
    Class: u32 {
        /// Invalid class
        NONE = 0x00000000,

        /// 32-bit objects
        ELF32 = 0x00000001,

        /// 64-bits objects
        ELF64 = 0x00000002,
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
    /// AMD HSA runtime
    AMDGPU_HSA,
    /// Linux TMS320C6000
    C6000_LINUX,
    /// ARM
    ARM,
    /// Standalone (embedded) applicatio
    STANDALONE,
    Unknown(u32),
}

impl From<u32> for OsAbi {
    fn from(value: u32) -> Self {
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
            _ => OsAbi::Unknown(value),
        }
    }
}

impl From<OsAbi> for u32 {
    fn from(value: OsAbi) -> u32 {
        match value {
            OsAbi::SYSTEMV => 0x00000000,
            OsAbi::HPUX => 0x00000001,
            OsAbi::NETBSD => 0x00000002,
            OsAbi::GNU => 0x00000003,
            OsAbi::LINUX => 0x00000003,
            OsAbi::HURD => 0x00000004,
            OsAbi::SOLARIS => 0x00000006,
            OsAbi::AIX => 0x00000007,
            OsAbi::IRIX => 0x00000008,
            OsAbi::FREEBSD => 0x00000009,
            OsAbi::TRU64 => 0x0000000a,
            OsAbi::MODESTO => 0x0000000b,
            OsAbi::OPENBSD => 0x0000000c,
            OsAbi::OPENVMS => 0x0000000d,
            OsAbi::NSK => 0x0000000e,
            OsAbi::AROS => 0x0000000f,
            OsAbi::FENIXOS => 0x00000010,
            OsAbi::CLOUDABI => 0x00000011,
            OsAbi::C6000_ELFABI => 0x00000040,
            OsAbi::AMDGPU_HSA => 0x00000040,
            OsAbi::C6000_LINUX => 0x00000041,
            OsAbi::ARM => 0x00000061,
            OsAbi::STANDALONE => 0x000000ff,
            OsAbi::Unknown(value) => value,
        }
    }
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    #[derive(PartialOrd, Ord)]
    /// Match the result `Elfxx_Ehdr.e_ident[EI_DATA]`
    ElfData: u32 {
        /// Invalid data encoding
        NONE = 0x00000000,
        /// 2's complement, little endian
        LSB = 0x00000001,
        /// 2's complement, big endian
        MSB = 0x00000002,
    }
}

/// Class which represents the ELF's header. This class mirrors the raw
/// ELF `Elfxx_Ehdr` structure
pub struct Header<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_Header>,
    _owner: PhantomData<&'a ffi::ELF_Binary>,
}

impl FromFFI<ffi::ELF_Header> for Header<'_> {
    fn from_ffi(hdr: cxx::UniquePtr<ffi::ELF_Header>) -> Self {
        Self {
            ptr: hdr,
            _owner: PhantomData,
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
        FileType::from(self.ptr.file_type())
    }

    /// Version of the object file format
    pub fn object_file_version(&self) -> Version {
        Version::from(self.ptr.object_file_version())
    }

    /// Return the object's class. `ELF64` or `ELF32`
    pub fn identity_class(&self) -> Class {
        Class::from(self.ptr.identity_class())
    }

    /// Return the ELF identity (`e_ident`) as a slice of 16 bytes
    pub fn identity(&self) -> &[u8] {
        to_slice!(self.ptr.identity());
    }

    /// Specify the data encoding
    pub fn identity_data(&self) -> ElfData {
        ElfData::from(self.ptr.identity_data())
    }

    /// Whether this header uses the MIPS n64 ELF encoding.
    pub fn is_mips_n64(&self) -> bool {
        self.ptr.is_mips_n64()
    }

    /// See: [`Header::object_file_version`]
    pub fn identity_version(&self) -> Version {
        Version::from(self.ptr.identity_version())
    }

    /// Identifies the version of the ABI for which the object is prepared
    pub fn identity_os_abi(&self) -> OsAbi {
        OsAbi::from(self.ptr.identity_os_abi())
    }

    /// ABI Version
    pub fn identity_abi_version(&self) -> u32 {
        self.ptr.identity_abi_version()
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
    /// This size should be 64 for an ``ELF64`` binary and 40 for an ``ELF32``.
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

    pub fn set_osabi(&mut self, osabi: OsAbi) {
        self.ptr.pin_mut().set_osabi(osabi.into());
    }
}

impl fmt::Debug for Header<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field("entrypoint", &self.entrypoint())
            .field("identity", &self.identity())
            .field("object_file_version", &self.object_file_version())
            .field("identity_class", &self.identity_class())
            .field("identity_os_abi", &self.identity_os_abi())
            .field("identity_abi_version", &self.identity_abi_version())
            .field("identity_data", &self.identity_data())
            .field("is_mips_n64", &self.is_mips_n64())
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

enum_from_int! {
    #[allow(non_camel_case_types)]
    Arch: u32 {
        NONE = 0x00000000,
        M32 = 0x00000001,
        SPARC = 0x00000002,
        I386 = 0x00000003,
        M68K = 0x00000004,
        M88K = 0x00000005,
        IAMCU = 0x00000006,
        I860 = 0x00000007,
        MIPS = 0x00000008,
        S370 = 0x00000009,
        MIPS_RS3_LE = 0x0000000a,
        PARISC = 0x0000000f,
        VPP500 = 0x00000011,
        SPARC32PLUS = 0x00000012,
        I60 = 0x00000013,
        PPC = 0x00000014,
        PPC64 = 0x00000015,
        S390 = 0x00000016,
        SPU = 0x00000017,
        V800 = 0x00000024,
        FR20 = 0x00000025,
        RH32 = 0x00000026,
        RCE = 0x00000027,
        ARM = 0x00000028,
        ALPHA = 0x00000029,
        SH = 0x0000002a,
        SPARCV9 = 0x0000002b,
        TRICORE = 0x0000002c,
        ARC = 0x0000002d,
        H8_300 = 0x0000002e,
        H8_300H = 0x0000002f,
        H8S = 0x00000030,
        H8_500 = 0x00000031,
        IA_64 = 0x00000032,
        MIPS_X = 0x00000033,
        COLDFIRE = 0x00000034,
        M68HC12 = 0x00000035,
        MMA = 0x00000036,
        PCP = 0x00000037,
        NCPU = 0x00000038,
        NDR1 = 0x00000039,
        STARCORE = 0x0000003a,
        ME16 = 0x0000003b,
        ST100 = 0x0000003c,
        TINYJ = 0x0000003d,
        X86_64 = 0x0000003e,
        PDSP = 0x0000003f,
        PDP10 = 0x00000040,
        PDP11 = 0x00000041,
        FX66 = 0x00000042,
        ST9PLUS = 0x00000043,
        ST7 = 0x00000044,
        M68HC16 = 0x00000045,
        M68HC11 = 0x00000046,
        M68HC08 = 0x00000047,
        M68HC05 = 0x00000048,
        SVX = 0x00000049,
        ST19 = 0x0000004a,
        VAX = 0x0000004b,
        CRIS = 0x0000004c,
        JAVELIN = 0x0000004d,
        FIREPATH = 0x0000004e,
        ZSP = 0x0000004f,
        MMIX = 0x00000050,
        HUANY = 0x00000051,
        PRISM = 0x00000052,
        AVR = 0x00000053,
        FR30 = 0x00000054,
        D10V = 0x00000055,
        D30V = 0x00000056,
        V850 = 0x00000057,
        M32R = 0x00000058,
        MN10300 = 0x00000059,
        MN10200 = 0x0000005a,
        PJ = 0x0000005b,
        OPENRISC = 0x0000005c,
        ARC_COMPACT = 0x0000005d,
        XTENSA = 0x0000005e,
        VIDEOCORE = 0x0000005f,
        TMM_GPP = 0x00000060,
        NS32K = 0x00000061,
        TPC = 0x00000062,
        SNP1K = 0x00000063,
        ST200 = 0x00000064,
        IP2K = 0x00000065,
        MAX = 0x00000066,
        CR = 0x00000067,
        F2MC16 = 0x00000068,
        MSP430 = 0x00000069,
        BLACKFIN = 0x0000006a,
        SE_C33 = 0x0000006b,
        SEP = 0x0000006c,
        ARCA = 0x0000006d,
        UNICORE = 0x0000006e,
        EXCESS = 0x0000006f,
        DXP = 0x00000070,
        ALTERA_NIOS2 = 0x00000071,
        CRX = 0x00000072,
        XGATE = 0x00000073,
        C166 = 0x00000074,
        M16C = 0x00000075,
        DSPIC30F = 0x00000076,
        CE = 0x00000077,
        M32C = 0x00000078,
        TSK3000 = 0x00000083,
        RS08 = 0x00000084,
        SHARC = 0x00000085,
        ECOG2 = 0x00000086,
        SCORE7 = 0x00000087,
        DSP24 = 0x00000088,
        VIDEOCORE3 = 0x00000089,
        LATTICEMICO32 = 0x0000008a,
        SE_C17 = 0x0000008b,
        TI_C6000 = 0x0000008c,
        TI_C2000 = 0x0000008d,
        TI_C5500 = 0x0000008e,
        MMDSP_PLUS = 0x000000a0,
        CYPRESS_M8C = 0x000000a1,
        R32C = 0x000000a2,
        TRIMEDIA = 0x000000a3,
        HEXAGON = 0x000000a4,
        M8051 = 0x000000a5,
        STXP7X = 0x000000a6,
        NDS32 = 0x000000a7,
        ECOG1 = 0x000000a8,
        //ECOG1X,
        MAXQ30 = 0x000000a9,
        XIMO16 = 0x000000aa,
        MANIK = 0x000000ab,
        CRAYNV2 = 0x000000ac,
        RX = 0x000000ad,
        METAG = 0x000000ae,
        MCST_ELBRUS = 0x000000af,
        ECOG16 = 0x000000b0,
        CR16 = 0x000000b1,
        ETPU = 0x000000b2,
        SLE9X = 0x000000b3,
        L10M = 0x000000b4,
        K10M = 0x000000b5,
        AARCH64 = 0x000000b7,
        AVR32 = 0x000000b9,
        STM8 = 0x000000ba,
        TILE64 = 0x000000bb,
        TILEPRO = 0x000000bc,
        CUDA = 0x000000be,
        TILEGX = 0x000000bf,
        CLOUDSHIELD = 0x000000c0,
        COREA_1ST = 0x000000c1,
        COREA_2ND = 0x000000c2,
        ARC_COMPACT2 = 0x000000c3,
        OPEN8 = 0x000000c4,
        RL78 = 0x000000c5,
        VIDEOCORE5 = 0x000000c6,
        M78KOR = 0x000000c7,
        M56800EX = 0x000000c8,
        BA1 = 0x000000c9,
        BA2 = 0x000000ca,
        XCORE = 0x000000cb,
        MCHP_PIC = 0x000000cc,
        INTEL205 = 0x000000cd,
        INTEL206 = 0x000000ce,
        INTEL207 = 0x000000cf,
        INTEL208 = 0x000000d0,
        INTEL209 = 0x000000d1,
        KM32 = 0x000000d2,
        KMX32 = 0x000000d3,
        KMX16 = 0x000000d4,
        KMX8 = 0x000000d5,
        KVARC = 0x000000d6,
        CDP = 0x000000d7,
        COGE = 0x000000d8,
        COOL = 0x000000d9,
        NORC = 0x000000da,
        CSR_KALIMBA = 0x000000db,
        AMDGPU = 0x000000e0,
        RISCV = 0x000000f3,
        BPF = 0x000000f7,
        CSKY = 0x000000fc,
        LOONGARCH = 0x00000102,
        ALPHA_ALT = 0x00009026,
    }
}
