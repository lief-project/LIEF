use lief_ffi as ffi;

use std::marker::PhantomData;

use crate::common::FromFFI;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Cpu {
    INTEL_8080,
    INTEL_8086,
    INTEL_80286,
    INTEL_80386,
    INTEL_80486,
    PENTIUM,
    PENTIUMPRO,
    PENTIUM3,
    MIPS,
    MIPS16,
    MIPS32,
    MIPS64,
    MIPSI,
    MIPSII,
    MIPSIII,
    MIPSIV,
    MIPSV,
    M68000,
    M68010,
    M68020,
    M68030,
    M68040,
    ALPHA,
    ALPHA_21164,
    ALPHA_21164A,
    ALPHA_21264,
    ALPHA_21364,
    PPC601,
    PPC603,
    PPC604,
    PPC620,
    PPCFP,
    PPCBE,
    SH3,
    SH3E,
    SH3DSP,
    SH4,
    SHMEDIA,
    ARM3,
    ARM4,
    ARM4T,
    ARM5,
    ARM5T,
    ARM6,
    ARM_XMAC,
    ARM_WMMX,
    ARM7,
    OMNI,
    IA64,
    IA64_2,
    CEE,
    AM33,
    M32R,
    TRICORE,
    X64,
    EBC,
    THUMB,
    ARMNT,
    ARM64,
    HYBRID_X86ARM64,
    ARM64EC,
    ARM64X,
    D3D11_SHADER,
    UNKNOWN(u16),
}

impl From<u16> for Cpu {
    fn from(value: u16) -> Self {
        match value {
            0x00000000 => Cpu::INTEL_8080,
            0x00000001 => Cpu::INTEL_8086,
            0x00000002 => Cpu::INTEL_80286,
            0x00000003 => Cpu::INTEL_80386,
            0x00000004 => Cpu::INTEL_80486,
            0x00000005 => Cpu::PENTIUM,
            0x00000006 => Cpu::PENTIUMPRO,
            0x00000007 => Cpu::PENTIUM3,
            0x00000010 => Cpu::MIPS,
            0x00000011 => Cpu::MIPS16,
            0x00000012 => Cpu::MIPS32,
            0x00000013 => Cpu::MIPS64,
            0x00000014 => Cpu::MIPSI,
            0x00000015 => Cpu::MIPSII,
            0x00000016 => Cpu::MIPSIII,
            0x00000017 => Cpu::MIPSIV,
            0x00000018 => Cpu::MIPSV,
            0x00000020 => Cpu::M68000,
            0x00000021 => Cpu::M68010,
            0x00000022 => Cpu::M68020,
            0x00000023 => Cpu::M68030,
            0x00000024 => Cpu::M68040,
            0x00000030 => Cpu::ALPHA,
            0x00000031 => Cpu::ALPHA_21164,
            0x00000032 => Cpu::ALPHA_21164A,
            0x00000033 => Cpu::ALPHA_21264,
            0x00000034 => Cpu::ALPHA_21364,
            0x00000040 => Cpu::PPC601,
            0x00000041 => Cpu::PPC603,
            0x00000042 => Cpu::PPC604,
            0x00000043 => Cpu::PPC620,
            0x00000044 => Cpu::PPCFP,
            0x00000045 => Cpu::PPCBE,
            0x00000050 => Cpu::SH3,
            0x00000051 => Cpu::SH3E,
            0x00000052 => Cpu::SH3DSP,
            0x00000053 => Cpu::SH4,
            0x00000054 => Cpu::SHMEDIA,
            0x00000060 => Cpu::ARM3,
            0x00000061 => Cpu::ARM4,
            0x00000062 => Cpu::ARM4T,
            0x00000063 => Cpu::ARM5,
            0x00000064 => Cpu::ARM5T,
            0x00000065 => Cpu::ARM6,
            0x00000066 => Cpu::ARM_XMAC,
            0x00000067 => Cpu::ARM_WMMX,
            0x00000068 => Cpu::ARM7,
            0x00000070 => Cpu::OMNI,
            0x00000080 => Cpu::IA64,
            0x00000081 => Cpu::IA64_2,
            0x00000090 => Cpu::CEE,
            0x000000a0 => Cpu::AM33,
            0x000000b0 => Cpu::M32R,
            0x000000c0 => Cpu::TRICORE,
            0x000000d0 => Cpu::X64,
            0x000000e0 => Cpu::EBC,
            0x000000f0 => Cpu::THUMB,
            0x000000f4 => Cpu::ARMNT,
            0x000000f6 => Cpu::ARM64,
            0x000000f7 => Cpu::HYBRID_X86ARM64,
            0x000000f8 => Cpu::ARM64EC,
            0x000000f9 => Cpu::ARM64X,
            0x00000100 => Cpu::D3D11_SHADER,
            _ => Cpu::UNKNOWN(value),

        }
    }
}

impl From<Cpu> for u16 {
    fn from(value: Cpu) -> u16 {
        match value {
            Cpu::INTEL_8080 => 0x00000000,
            Cpu::INTEL_8086 => 0x00000001,
            Cpu::INTEL_80286 => 0x00000002,
            Cpu::INTEL_80386 => 0x00000003,
            Cpu::INTEL_80486 => 0x00000004,
            Cpu::PENTIUM => 0x00000005,
            Cpu::PENTIUMPRO => 0x00000006,
            Cpu::PENTIUM3 => 0x00000007,
            Cpu::MIPS => 0x00000010,
            Cpu::MIPS16 => 0x00000011,
            Cpu::MIPS32 => 0x00000012,
            Cpu::MIPS64 => 0x00000013,
            Cpu::MIPSI => 0x00000014,
            Cpu::MIPSII => 0x00000015,
            Cpu::MIPSIII => 0x00000016,
            Cpu::MIPSIV => 0x00000017,
            Cpu::MIPSV => 0x00000018,
            Cpu::M68000 => 0x00000020,
            Cpu::M68010 => 0x00000021,
            Cpu::M68020 => 0x00000022,
            Cpu::M68030 => 0x00000023,
            Cpu::M68040 => 0x00000024,
            Cpu::ALPHA => 0x00000030,
            Cpu::ALPHA_21164 => 0x00000031,
            Cpu::ALPHA_21164A => 0x00000032,
            Cpu::ALPHA_21264 => 0x00000033,
            Cpu::ALPHA_21364 => 0x00000034,
            Cpu::PPC601 => 0x00000040,
            Cpu::PPC603 => 0x00000041,
            Cpu::PPC604 => 0x00000042,
            Cpu::PPC620 => 0x00000043,
            Cpu::PPCFP => 0x00000044,
            Cpu::PPCBE => 0x00000045,
            Cpu::SH3 => 0x00000050,
            Cpu::SH3E => 0x00000051,
            Cpu::SH3DSP => 0x00000052,
            Cpu::SH4 => 0x00000053,
            Cpu::SHMEDIA => 0x00000054,
            Cpu::ARM3 => 0x00000060,
            Cpu::ARM4 => 0x00000061,
            Cpu::ARM4T => 0x00000062,
            Cpu::ARM5 => 0x00000063,
            Cpu::ARM5T => 0x00000064,
            Cpu::ARM6 => 0x00000065,
            Cpu::ARM_XMAC => 0x00000066,
            Cpu::ARM_WMMX => 0x00000067,
            Cpu::ARM7 => 0x00000068,
            Cpu::OMNI => 0x00000070,
            Cpu::IA64 => 0x00000080,
            Cpu::IA64_2 => 0x00000081,
            Cpu::CEE => 0x00000090,
            Cpu::AM33 => 0x000000a0,
            Cpu::M32R => 0x000000b0,
            Cpu::TRICORE => 0x000000c0,
            Cpu::X64 => 0x000000d0,
            Cpu::EBC => 0x000000e0,
            Cpu::THUMB => 0x000000f0,
            Cpu::ARMNT => 0x000000f4,
            Cpu::ARM64 => 0x000000f6,
            Cpu::HYBRID_X86ARM64 => 0x000000f7,
            Cpu::ARM64EC => 0x000000f8,
            Cpu::ARM64X => 0x000000f9,
            Cpu::D3D11_SHADER => 0x00000100,
            Cpu::UNKNOWN(value) => value,

        }
    }
}


#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Lang {
    C,
    CPP,
    FORTRAN,
    MASM,
    PASCAL_LANG,
    BASIC,
    COBOL,
    LINK,
    CVTRES,
    CVTPGD,
    CSHARP,
    VB,
    ILASM,
    JAVA,
    JSCRIPT,
    MSIL,
    HLSL,
    OBJC,
    OBJCPP,
    SWIFT,
    ALIASOBJ,
    RUST,
    GO,
    UNKNOWN(u8),
}

impl From<u8> for Lang {
    fn from(value: u8) -> Self {
        match value {
            0x00000000 => Lang::C,
            0x00000001 => Lang::CPP,
            0x00000002 => Lang::FORTRAN,
            0x00000003 => Lang::MASM,
            0x00000004 => Lang::PASCAL_LANG,
            0x00000005 => Lang::BASIC,
            0x00000006 => Lang::COBOL,
            0x00000007 => Lang::LINK,
            0x00000008 => Lang::CVTRES,
            0x00000009 => Lang::CVTPGD,
            0x0000000a => Lang::CSHARP,
            0x0000000b => Lang::VB,
            0x0000000c => Lang::ILASM,
            0x0000000d => Lang::JAVA,
            0x0000000e => Lang::JSCRIPT,
            0x0000000f => Lang::MSIL,
            0x00000010 => Lang::HLSL,
            0x00000011 => Lang::OBJC,
            0x00000012 => Lang::OBJCPP,
            0x00000013 => Lang::SWIFT,
            0x00000014 => Lang::ALIASOBJ,
            0x00000015 => Lang::RUST,
            0x00000016 => Lang::GO,
            _ => Lang::UNKNOWN(value),

        }
    }
}
impl From<Lang> for u8 {
    fn from(value: Lang) -> u8 {
        match value {
            Lang::C => 0x00000000,
            Lang::CPP => 0x00000001,
            Lang::FORTRAN => 0x00000002,
            Lang::MASM => 0x00000003,
            Lang::PASCAL_LANG => 0x00000004,
            Lang::BASIC => 0x00000005,
            Lang::COBOL => 0x00000006,
            Lang::LINK => 0x00000007,
            Lang::CVTRES => 0x00000008,
            Lang::CVTPGD => 0x00000009,
            Lang::CSHARP => 0x0000000a,
            Lang::VB => 0x0000000b,
            Lang::ILASM => 0x0000000c,
            Lang::JAVA => 0x0000000d,
            Lang::JSCRIPT => 0x0000000e,
            Lang::MSIL => 0x0000000f,
            Lang::HLSL => 0x00000010,
            Lang::OBJC => 0x00000011,
            Lang::OBJCPP => 0x00000012,
            Lang::SWIFT => 0x00000013,
            Lang::ALIASOBJ => 0x00000014,
            Lang::RUST => 0x00000015,
            Lang::GO => 0x00000016,
            Lang::UNKNOWN(value) => value,

        }
    }
}


/// This class wraps build metadata represented by the codeview symbols:
/// `S_COMPILE3, S_COMPILE2, S_BUILDINFO`
pub struct BuildMetadata<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_BuildMetadata>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::PDB_BuildMetadata> for BuildMetadata<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PDB_BuildMetadata>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl BuildMetadata<'_> {
    /// Version of the frontend (e.g. `19.36.32537`)
    pub fn frontend_version(&self) -> Version {
        Version::from_ffi(self.ptr.frontend_version())
    }

    /// Version of the backend (e.g. `14.36.32537`)
    pub fn backend_version(&self) -> Version {
        Version::from_ffi(self.ptr.backend_version())
    }

    /// Version of the *tool* as a string. For instance, `Microsoft (R) CVTRES`,
    /// `Microsoft (R) LINK`.
    pub fn version(&self) -> String {
        self.ptr.version().to_string()
    }

    /// Source language
    pub fn language(&self) -> Lang {
        Lang::from(self.ptr.language())
    }

    /// Target CPU
    pub fn target_cpu(&self) -> Cpu {
        Cpu::from(self.ptr.target_cpu())
    }

    /// Environment information represented by the `S_ENVBLOCK` symbol
    pub fn env(&self) -> Vec<String> {
        self.ptr.env().iter().map(|e| e.to_string()).collect::<Vec<String>>()
    }

    /// Build information represented by the `S_BUILDINFO` symbol
    pub fn build_info(&self) -> Option<BuildInfo> {
        BuildInfo::from_ffi(self.ptr.build_info())
    }
}

impl std::fmt::Display for BuildMetadata<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}


impl std::fmt::Debug for BuildMetadata<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuildMetadata")
            .field("frontend_version", &self.frontend_version())
            .field("backend_version", &self.backend_version())
            .field("version", &self.version())
            .field("language", &self.language())
            .field("target_cpu", &self.target_cpu())
            .field("env", &self.env())
            .field("build_info", &self.build_info())
            .finish()
    }
}


/// This structure represents a version for the backend or the frontend.
#[derive(Debug)]
pub struct Version {
    /// Major Version
    pub major: u16,

    /// Minor Version
    pub minor: u16,

    /// Build Version
    pub build: u16,

    /// Quick Fix Engineeringa version
    pub qfe: u16,
}

impl Version {
    #[doc(hidden)]
    pub fn from_ffi(ffi: cxx::UniquePtr<cxx::CxxVector<u16>>) -> Self {
        let vec = ffi.as_ref().unwrap();
        Self {
            major: *vec.get(0).unwrap(),
            minor: *vec.get(1).unwrap(),
            build: *vec.get(2).unwrap(),
            qfe: *vec.get(3).unwrap(),
        }
    }
}

/// This structure represents information wrapped by the `S_BUILDINFO`
/// symbol
#[derive(Debug)]
pub struct BuildInfo {
    /// Working directory where the *build tool* was invoked
    pub cwd: String,

    /// Path to the build tool (e.g. `C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.36.32532\bin\HostX64\x64\CL.exe`)
    pub build_tool: String,

    /// Source file consumed by the *build tool*
    pub source_file: String,

    /// PDB path
    pub pdb: String,

    /// Command line arguments used to invoke the *build tool*
    pub command_line: String,
}

impl BuildInfo {
    #[doc(hidden)]
    pub fn from_ffi(ffi: cxx::UniquePtr<cxx::CxxVector<cxx::CxxString>>) -> Option<Self> {
        let vec = ffi.as_ref().unwrap();
        if vec.is_empty() {
            return None;
        }

        assert_eq!(vec.len(), 5);
        Some(Self {
            cwd: vec.get(0).unwrap().to_string(),
            build_tool: vec.get(1).unwrap().to_string(),
            source_file: vec.get(2).unwrap().to_string(),
            pdb: vec.get(3).unwrap().to_string(),
            command_line: vec.get(4).unwrap().to_string(),
        })
    }
}
