use super::Command;
use crate::common::FromFFI;
use crate::{declare_iterator, to_slice};
use lief_ffi as ffi;
use std::marker::PhantomData;

/// Class representing the `LC_FUNCTION_VARIANTS` load command.
///
/// Introduced publicly in `dyld-1284.13` (April 2025), this command supports
/// **function multiversioning**, the ability to associate multiple implementations
/// of the same function, each optimized for a specific platform, architecture,
/// or runtime context.
///
/// At runtime, the system dispatches the most appropriate variant based on
/// hardware capabilities or execution environment.
///
/// For example:
///
/// ```cpp
/// FUNCTION_VARIANT_TABLE(my_function,
///   { (void*)my_function$Rosetta,  "rosetta" }, // Rosetta translation
///   { (void*)my_function$Haswell,  "haswell" }, // Haswell-optimized
///   { (void*)my_function$Base,     "default" }  // Default fallback
/// );
/// ```
pub struct FunctionVariants<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_FunctionVariants>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

impl FunctionVariants<'_> {
    /// Offset in the `__LINKEDIT` segment where the payload is located
    pub fn data_offset(&self) -> u32 {
        self.ptr.data_offset()
    }

    /// Size of the payload
    pub fn data_size(&self) -> u32 {
        self.ptr.data_size()
    }

    /// Raw payload as a slice of bytes
    pub fn content(&self) -> &[u8] {
        to_slice!(self.ptr.content());
    }

    /// Iterator over the different [`RuntimeTable`] entries located in the content
    /// of this `__LINKEDIT` command
    pub fn runtime_table(&self) -> RuntimeTables<'_> {
        RuntimeTables::new(self.ptr.runtime_table())
    }
}

impl std::fmt::Debug for FunctionVariants<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("FunctionVariants")
            .field("base", &base)
            .field("data_offset", &self.data_offset())
            .field("data_size", &self.data_size())
            .finish()
    }
}

impl FromFFI<ffi::MachO_FunctionVariants> for FunctionVariants<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_FunctionVariants>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Command for FunctionVariants<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

/// Represents a runtime table of function variants sharing a common namespace
/// (referred to internally as `FunctionVariantsRuntimeTable` in `dyld`).
///
/// Each table holds multiple [`RuntimeTableEntry`] instances that map to
/// function implementations optimized for a given [`Kind`].
pub struct RuntimeTable<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_FunctionVariants_RuntimeTable>,
    _owner: PhantomData<&'a ffi::MachO_FunctionVariants>,
}

impl FromFFI<ffi::MachO_FunctionVariants_RuntimeTable> for RuntimeTable<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_FunctionVariants_RuntimeTable>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl RuntimeTable<'_> {
    /// Kind of this runtime table
    pub fn kind(&self) -> Kind {
        Kind::from(self.ptr.kind())
    }

    /// Original offset in the payload
    pub fn offset(&self) -> u32 {
        self.ptr.offset()
    }

    /// Iterator over the different [`RuntimeTableEntry`] entries
    pub fn entries(&self) -> RuntimeTableEntries<'_> {
        RuntimeTableEntries::new(self.ptr.entries())
    }
}

impl std::fmt::Debug for RuntimeTable<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeTable")
            .field("kind", &self.kind())
            .field("offset", &self.offset())
            .finish()
    }
}

impl std::fmt::Display for RuntimeTable<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}


#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
/// Enumeration describing the namespace or category of a function variant.
///
/// Each [`RuntimeTable`] is associated with one [`Kind`],
/// which indicates the domain or context under which its variant entries
/// should be considered valid or applicable.
///
/// These categories map to the runtime dispatch logic used by `dyld`
/// when selecting the optimal function variant.
pub enum Kind {
    /// Variants that apply on a per-process basis
    PER_PROCESS,

    /// Variants that are selected based on system-wide capabilities or configurations.
    SYSTEM_WIDE,

    /// Variants optimized for the ARM64 architecture.
    ARM64,

    /// Variants optimized for the x86-64 architecture.
    X86_64,

    /// Fallback/default kind when the category is not recognized.
    UNKNOWN(u32),
}

impl From<u32> for Kind {
    fn from(value: u32) -> Self {
        match value {
            0x00000001 => Kind::PER_PROCESS,
            0x00000002 => Kind::SYSTEM_WIDE,
            0x00000003 => Kind::ARM64,
            0x00000004 => Kind::X86_64,
            _ => Kind::UNKNOWN(value),

        }
    }
}
impl From<Kind> for u32 {
    fn from(value: Kind) -> u32 {
        match value {
            Kind::PER_PROCESS => 0x00000001,
            Kind::SYSTEM_WIDE => 0x00000002,
            Kind::ARM64 => 0x00000003,
            Kind::X86_64 => 0x00000004,
            Kind::UNKNOWN(value) => value,

        }
    }
}


/// This class exposes information about a given implementation.
pub struct RuntimeTableEntry<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_FunctionVariants_RuntimeTableEntry>,
    _owner: PhantomData<&'a ffi::MachO_FunctionVariants_RuntimeTable>,
}

impl FromFFI<ffi::MachO_FunctionVariants_RuntimeTableEntry> for RuntimeTableEntry<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_FunctionVariants_RuntimeTableEntry>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl RuntimeTableEntry<'_> {
    /// The relative address of the implementation or an index if [`RuntimeTableEntry::another_table`] is set.
    pub fn implementation(&self) -> u32 {
        self.ptr.implementation()
    }

    /// Indicates whether [`RuntimeTableEntry::implementation`] refers to an entry in another runtime table,
    /// rather than a direct function implementation address.
    pub fn another_table(&self) -> bool {
        self.ptr.another_table()
    }

    /// The `flagBitNums` value as a slice of bytes
    pub fn flag_bit_nums(&self) -> &[u8] {
        to_slice!(self.ptr.flag_bit_nums());
    }

    /// Return the **interpreted** [`RuntimeTableEntry::flag_bit_nums`]
    pub fn flags(&self) -> Vec<Flag> {
        let vec = Vec::from(self.ptr.flags().as_slice());
        vec.iter().map(|e| Flag::from(*e)).collect()
    }
}

impl std::fmt::Debug for RuntimeTableEntry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeTableEntry")
            .field("implementation", &self.implementation())
            .field("another_table", &self.another_table())
            .field("flag_bit_nums", &self.flag_bit_nums())
            .field("flags", &self.flags())
            .finish()
    }
}

impl std::fmt::Display for RuntimeTableEntry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}


#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
/// Flags describing the target platform, environment, or architecture
/// for a given function implementation.
///
/// These are encoded as a `uint32_t`, where high bits determine the namespace
/// ([`Kind`]), and the lower bits encode the specific capability.
pub enum Flag {
    ARM64_DEFAULT,
    ARM64_FLAGM,
    ARM64_FLAGM2,
    ARM64_FHM,
    ARM64_DOTPROD,
    ARM64_SHA3,
    ARM64_RDM,
    ARM64_LSE,
    ARM64_SHA256,
    ARM64_SHA512,
    ARM64_SHA1,
    ARM64_AES,
    ARM64_PMULL,
    ARM64_SPECRES,
    ARM64_SB,
    ARM64_FRINTTS,
    ARM64_LRCPC,
    ARM64_LRCPC2,
    ARM64_FCMA,
    ARM64_JSCVT,
    ARM64_PAUTH,
    ARM64_PAUTH2,
    ARM64_FPAC,
    ARM64_DPB,
    ARM64_DPB2,
    ARM64_BF16,
    ARM64_I8MM,
    ARM64_WFXT,
    ARM64_RPRES,
    ARM64_ECV,
    ARM64_AFP,
    ARM64_LSE2,
    ARM64_CSV2,
    ARM64_CVS3,
    ARM64_DIT,
    ARM64_FP16,
    ARM64_SSBS,
    ARM64_BTI,
    ARM64_SME,
    ARM64_SME2,
    ARM64_SMEF64F64,
    ARM64_SMEI16I64,
    ARM64_SMEF32F32,
    ARM64_SMEBI32I32,
    ARM64_SMEB16F32,
    ARM64_SMEF16F32,
    ARM64_SMEI8I32,
    ARM64_SMEI16I32,
    ARM64_ADVSIMD,
    ARM64_ADVSIMDHPFP,
    ARM64_CRC32,
    X86_64_DEFAULT,
    X86_64_SSE41,
    X86_64_FMA,
    X86_64_AVX,
    X86_64_AVX2,
    X86_64_AVX512F,
    X86_64_AVX512BW,
    X86_64_BMI1,
    X86_64_ROSETTA,
    X86_64_HASWELL,
    X86_64_IVYBRIDGE,
    X86_64_NEHALEM,
    SYSTEM_WIDE_DEFAULT,
    SYSTEM_WIDE_INTERNAL_INSTALL,
    SYSTEM_WIDE_CUSTOMER_INSTALL,
    SYSTEM_WIDE_LOCKDOWN,
    PER_PROCESS_DEFAULT,
    PER_PROCESS_TRANSLATED,
    PER_PROCESS_NO_OVERREAD,
    UNKNOWN(u32),
}

impl From<u32> for Flag {
    fn from(value: u32) -> Self {
        match value {
            0x00300000 => Flag::ARM64_DEFAULT,
            0x00300001 => Flag::ARM64_FLAGM,
            0x00300002 => Flag::ARM64_FLAGM2,
            0x00300003 => Flag::ARM64_FHM,
            0x00300004 => Flag::ARM64_DOTPROD,
            0x00300005 => Flag::ARM64_SHA3,
            0x00300006 => Flag::ARM64_RDM,
            0x00300007 => Flag::ARM64_LSE,
            0x00300008 => Flag::ARM64_SHA256,
            0x00300009 => Flag::ARM64_SHA512,
            0x0030000a => Flag::ARM64_SHA1,
            0x0030000b => Flag::ARM64_AES,
            0x0030000c => Flag::ARM64_PMULL,
            0x0030000d => Flag::ARM64_SPECRES,
            0x0030000e => Flag::ARM64_SB,
            0x0030000f => Flag::ARM64_FRINTTS,
            0x00300010 => Flag::ARM64_LRCPC,
            0x00300011 => Flag::ARM64_LRCPC2,
            0x00300012 => Flag::ARM64_FCMA,
            0x00300013 => Flag::ARM64_JSCVT,
            0x00300014 => Flag::ARM64_PAUTH,
            0x00300015 => Flag::ARM64_PAUTH2,
            0x00300016 => Flag::ARM64_FPAC,
            0x00300017 => Flag::ARM64_DPB,
            0x00300018 => Flag::ARM64_DPB2,
            0x00300019 => Flag::ARM64_BF16,
            0x0030001a => Flag::ARM64_I8MM,
            0x0030001b => Flag::ARM64_WFXT,
            0x0030001c => Flag::ARM64_RPRES,
            0x0030001d => Flag::ARM64_ECV,
            0x0030001e => Flag::ARM64_AFP,
            0x0030001f => Flag::ARM64_LSE2,
            0x00300020 => Flag::ARM64_CSV2,
            0x00300021 => Flag::ARM64_CVS3,
            0x00300022 => Flag::ARM64_DIT,
            0x00300023 => Flag::ARM64_FP16,
            0x00300024 => Flag::ARM64_SSBS,
            0x00300025 => Flag::ARM64_BTI,
            0x0030002c => Flag::ARM64_SME,
            0x0030002d => Flag::ARM64_SME2,
            0x0030002e => Flag::ARM64_SMEF64F64,
            0x0030002f => Flag::ARM64_SMEI16I64,
            0x00300030 => Flag::ARM64_SMEF32F32,
            0x00300031 => Flag::ARM64_SMEBI32I32,
            0x00300032 => Flag::ARM64_SMEB16F32,
            0x00300033 => Flag::ARM64_SMEF16F32,
            0x00300034 => Flag::ARM64_SMEI8I32,
            0x00300035 => Flag::ARM64_SMEI16I32,
            0x00300036 => Flag::ARM64_ADVSIMD,
            0x00300037 => Flag::ARM64_ADVSIMDHPFP,
            0x00300038 => Flag::ARM64_CRC32,
            0x00400000 => Flag::X86_64_DEFAULT,
            0x00400001 => Flag::X86_64_SSE41,
            0x00400002 => Flag::X86_64_FMA,
            0x00400003 => Flag::X86_64_AVX,
            0x00400004 => Flag::X86_64_AVX2,
            0x00400005 => Flag::X86_64_AVX512F,
            0x00400006 => Flag::X86_64_AVX512BW,
            0x00400007 => Flag::X86_64_BMI1,
            0x00400008 => Flag::X86_64_ROSETTA,
            0x00400009 => Flag::X86_64_HASWELL,
            0x0040000a => Flag::X86_64_IVYBRIDGE,
            0x0040000b => Flag::X86_64_NEHALEM,
            0x00200000 => Flag::SYSTEM_WIDE_DEFAULT,
            0x00200001 => Flag::SYSTEM_WIDE_INTERNAL_INSTALL,
            0x00200002 => Flag::SYSTEM_WIDE_CUSTOMER_INSTALL,
            0x00200003 => Flag::SYSTEM_WIDE_LOCKDOWN,
            0x00100000 => Flag::PER_PROCESS_DEFAULT,
            0x00100001 => Flag::PER_PROCESS_TRANSLATED,
            0x00100003 => Flag::PER_PROCESS_NO_OVERREAD,
            _ => Flag::UNKNOWN(value),

        }
    }
}
impl From<Flag> for u32 {
    fn from(value: Flag) -> u32 {
        match value {
            Flag::ARM64_DEFAULT => 0x00300000,
            Flag::ARM64_FLAGM => 0x00300001,
            Flag::ARM64_FLAGM2 => 0x00300002,
            Flag::ARM64_FHM => 0x00300003,
            Flag::ARM64_DOTPROD => 0x00300004,
            Flag::ARM64_SHA3 => 0x00300005,
            Flag::ARM64_RDM => 0x00300006,
            Flag::ARM64_LSE => 0x00300007,
            Flag::ARM64_SHA256 => 0x00300008,
            Flag::ARM64_SHA512 => 0x00300009,
            Flag::ARM64_SHA1 => 0x0030000a,
            Flag::ARM64_AES => 0x0030000b,
            Flag::ARM64_PMULL => 0x0030000c,
            Flag::ARM64_SPECRES => 0x0030000d,
            Flag::ARM64_SB => 0x0030000e,
            Flag::ARM64_FRINTTS => 0x0030000f,
            Flag::ARM64_LRCPC => 0x00300010,
            Flag::ARM64_LRCPC2 => 0x00300011,
            Flag::ARM64_FCMA => 0x00300012,
            Flag::ARM64_JSCVT => 0x00300013,
            Flag::ARM64_PAUTH => 0x00300014,
            Flag::ARM64_PAUTH2 => 0x00300015,
            Flag::ARM64_FPAC => 0x00300016,
            Flag::ARM64_DPB => 0x00300017,
            Flag::ARM64_DPB2 => 0x00300018,
            Flag::ARM64_BF16 => 0x00300019,
            Flag::ARM64_I8MM => 0x0030001a,
            Flag::ARM64_WFXT => 0x0030001b,
            Flag::ARM64_RPRES => 0x0030001c,
            Flag::ARM64_ECV => 0x0030001d,
            Flag::ARM64_AFP => 0x0030001e,
            Flag::ARM64_LSE2 => 0x0030001f,
            Flag::ARM64_CSV2 => 0x00300020,
            Flag::ARM64_CVS3 => 0x00300021,
            Flag::ARM64_DIT => 0x00300022,
            Flag::ARM64_FP16 => 0x00300023,
            Flag::ARM64_SSBS => 0x00300024,
            Flag::ARM64_BTI => 0x00300025,
            Flag::ARM64_SME => 0x0030002c,
            Flag::ARM64_SME2 => 0x0030002d,
            Flag::ARM64_SMEF64F64 => 0x0030002e,
            Flag::ARM64_SMEI16I64 => 0x0030002f,
            Flag::ARM64_SMEF32F32 => 0x00300030,
            Flag::ARM64_SMEBI32I32 => 0x00300031,
            Flag::ARM64_SMEB16F32 => 0x00300032,
            Flag::ARM64_SMEF16F32 => 0x00300033,
            Flag::ARM64_SMEI8I32 => 0x00300034,
            Flag::ARM64_SMEI16I32 => 0x00300035,
            Flag::ARM64_ADVSIMD => 0x00300036,
            Flag::ARM64_ADVSIMDHPFP => 0x00300037,
            Flag::ARM64_CRC32 => 0x00300038,
            Flag::X86_64_DEFAULT => 0x00400000,
            Flag::X86_64_SSE41 => 0x00400001,
            Flag::X86_64_FMA => 0x00400002,
            Flag::X86_64_AVX => 0x00400003,
            Flag::X86_64_AVX2 => 0x00400004,
            Flag::X86_64_AVX512F => 0x00400005,
            Flag::X86_64_AVX512BW => 0x00400006,
            Flag::X86_64_BMI1 => 0x00400007,
            Flag::X86_64_ROSETTA => 0x00400008,
            Flag::X86_64_HASWELL => 0x00400009,
            Flag::X86_64_IVYBRIDGE => 0x0040000a,
            Flag::X86_64_NEHALEM => 0x0040000b,
            Flag::SYSTEM_WIDE_DEFAULT => 0x00200000,
            Flag::SYSTEM_WIDE_INTERNAL_INSTALL => 0x00200001,
            Flag::SYSTEM_WIDE_CUSTOMER_INSTALL => 0x00200002,
            Flag::SYSTEM_WIDE_LOCKDOWN => 0x00200003,
            Flag::PER_PROCESS_DEFAULT => 0x00100000,
            Flag::PER_PROCESS_TRANSLATED => 0x00100001,
            Flag::PER_PROCESS_NO_OVERREAD => 0x00100003,
            Flag::UNKNOWN(value) => value,

        }
    }
}

declare_iterator!(
    RuntimeTables,
    RuntimeTable<'a>,
    ffi::MachO_FunctionVariants_RuntimeTable,
    ffi::MachO_FunctionVariants,
    ffi::MachO_FunctionVariants_it_runtime_table
);

declare_iterator!(
    RuntimeTableEntries,
    RuntimeTableEntry<'a>,
    ffi::MachO_FunctionVariants_RuntimeTableEntry,
    ffi::MachO_FunctionVariants_RuntimeTable,
    ffi::MachO_FunctionVariants_RuntimeTable_it_entries
);
