use lief_ffi as ffi;

use std::marker::PhantomData;

use crate::common::FromFFI;
use crate::enum_from_int;

enum_from_int! {
    #[allow(non_camel_case_types)]
    Cpu: u16 {
        INTEL_8080 = 0x00000000,
        INTEL_8086 = 0x00000001,
        INTEL_80286 = 0x00000002,
        INTEL_80386 = 0x00000003,
        INTEL_80486 = 0x00000004,
        PENTIUM = 0x00000005,
        PENTIUMPRO = 0x00000006,
        PENTIUM3 = 0x00000007,
        MIPS = 0x00000010,
        MIPS16 = 0x00000011,
        MIPS32 = 0x00000012,
        MIPS64 = 0x00000013,
        MIPSI = 0x00000014,
        MIPSII = 0x00000015,
        MIPSIII = 0x00000016,
        MIPSIV = 0x00000017,
        MIPSV = 0x00000018,
        M68000 = 0x00000020,
        M68010 = 0x00000021,
        M68020 = 0x00000022,
        M68030 = 0x00000023,
        M68040 = 0x00000024,
        ALPHA = 0x00000030,
        ALPHA_21164 = 0x00000031,
        ALPHA_21164A = 0x00000032,
        ALPHA_21264 = 0x00000033,
        ALPHA_21364 = 0x00000034,
        PPC601 = 0x00000040,
        PPC603 = 0x00000041,
        PPC604 = 0x00000042,
        PPC620 = 0x00000043,
        PPCFP = 0x00000044,
        PPCBE = 0x00000045,
        SH3 = 0x00000050,
        SH3E = 0x00000051,
        SH3DSP = 0x00000052,
        SH4 = 0x00000053,
        SHMEDIA = 0x00000054,
        ARM3 = 0x00000060,
        ARM4 = 0x00000061,
        ARM4T = 0x00000062,
        ARM5 = 0x00000063,
        ARM5T = 0x00000064,
        ARM6 = 0x00000065,
        ARM_XMAC = 0x00000066,
        ARM_WMMX = 0x00000067,
        ARM7 = 0x00000068,
        OMNI = 0x00000070,
        IA64 = 0x00000080,
        IA64_2 = 0x00000081,
        CEE = 0x00000090,
        AM33 = 0x000000a0,
        M32R = 0x000000b0,
        TRICORE = 0x000000c0,
        X64 = 0x000000d0,
        EBC = 0x000000e0,
        THUMB = 0x000000f0,
        ARMNT = 0x000000f4,
        ARM64 = 0x000000f6,
        HYBRID_X86ARM64 = 0x000000f7,
        ARM64EC = 0x000000f8,
        ARM64X = 0x000000f9,
        D3D11_SHADER = 0x00000100,
    }
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    Lang: u8 {
        C = 0x00000000,
        CPP = 0x00000001,
        FORTRAN = 0x00000002,
        MASM = 0x00000003,
        PASCAL_LANG = 0x00000004,
        BASIC = 0x00000005,
        COBOL = 0x00000006,
        LINK = 0x00000007,
        CVTRES = 0x00000008,
        CVTPGD = 0x00000009,
        CSHARP = 0x0000000a,
        VB = 0x0000000b,
        ILASM = 0x0000000c,
        JAVA = 0x0000000d,
        JSCRIPT = 0x0000000e,
        MSIL = 0x0000000f,
        HLSL = 0x00000010,
        OBJC = 0x00000011,
        OBJCPP = 0x00000012,
        SWIFT = 0x00000013,
        ALIASOBJ = 0x00000014,
        RUST = 0x00000015,
        GO = 0x00000016,
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
        self.ptr
            .env()
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<String>>()
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
