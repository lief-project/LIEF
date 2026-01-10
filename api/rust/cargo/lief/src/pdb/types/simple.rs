use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;
use crate::pdb::types::PdbType;

/// This class represents a primitive types (int, float, ...) which are
/// also named *simple* types in the PDB format.
pub struct Simple<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_types_Simple>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::PDB_types_Simple> for Simple<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::PDB_types_Simple>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SimpleType {
    /// Void type (return type or void*)
    VOID,

    // --- Characters ---
    /// Signed Character
    SCHAR,
    /// Unsigned Character
    UCHAR,
    /// "Real" Character (char)
    RCHAR,

    // --- Unicode / Wide Characters ---
    /// Wide Character (wchar_t)
    WCHAR,
    /// 16-bit Character (char16_t)
    CHAR16,
    /// 32-bit Character (char32_t)
    CHAR32,
    /// 8-bit Character (char8_t)
    CHAR8,

    // --- Bytes ---
    /// Signed Byte
    SBYTE,
    /// Unsigned Byte
    UBYTE,

    // --- Short (16-bit) ---
    /// Signed Short
    SSHORT,
    /// Unsigned Short
    USHORT,

    /// Explicit Signed 16-bit Integer
    SINT16,
    /// Explicit Unsigned 16-bit Integer
    UINT16,

    // --- Long (32-bit) ---
    /// Signed Long
    SLONG,
    /// Unsigned Long
    ULONG,

    /// Explicit Signed 32-bit Integer
    SINT32,
    /// Explicit Unsigned 32-bit Integer
    UINT32,

    // --- Quad (64-bit) ---
    /// Signed Quadword
    SQUAD,
    /// Unsigned Quadword
    UQUAD,

    /// Explicit Signed 64-bit Integer
    SINT64,
    /// Explicit Unsigned 64-bit Integer
    UINT64,

    // --- Octa (128-bit) ---
    /// Signed Octaword
    SOCTA,
    /// Unsigned Octaword
    UOCTA,

    /// Explicit Signed 128-bit Integer
    SINT128,
    /// Explicit Unsigned 128-bit Integer
    UINT128,

    // --- Floating Point ---
    /// 16-bit Floating point
    FLOAT16,
    /// 32-bit Floating point (float)
    FLOAT32,
    FLOAT32_PARTIAL_PRECISION,

    /// 48-bit Floating point
    FLOAT48,
    /// 64-bit Floating point (double)
    FLOAT64,
    /// 80-bit Floating point
    FLOAT80,
    /// 128-bit Floating point
    FLOAT128,

    // --- Complex Numbers ---
    COMPLEX16,
    COMPLEX32,
    COMPLEX32_PARTIAL_PRECISION,
    COMPLEX48,
    COMPLEX64,
    COMPLEX80,
    COMPLEX128,

    // --- Booleans ---
    /// 8-bit Boolean
    BOOL8,
    /// 16-bit Boolean
    BOOL16,
    /// 32-bit Boolean
    BOOL32,
    /// 64-bit Boolean
    BOOL64,
    /// 128-bit Boolean
    BOOL128,

    UNKNOWN(u32),
}

impl From<u32> for SimpleType {
    fn from(value: u32) -> Self {
        match value {
            0x0003 => SimpleType::VOID,
            0x0010 => SimpleType::SCHAR,
            0x0020 => SimpleType::UCHAR,
            0x0070 => SimpleType::RCHAR,
            0x0071 => SimpleType::WCHAR,
            0x007a => SimpleType::CHAR16,
            0x007b => SimpleType::CHAR32,
            0x007c => SimpleType::CHAR8,
            0x0068 => SimpleType::SBYTE,
            0x0069 => SimpleType::UBYTE,
            0x0011 => SimpleType::SSHORT,
            0x0021 => SimpleType::USHORT,
            0x0072 => SimpleType::SINT16,
            0x0073 => SimpleType::UINT16,
            0x0012 => SimpleType::SLONG,
            0x0022 => SimpleType::ULONG,
            0x0074 => SimpleType::SINT32,
            0x0075 => SimpleType::UINT32,
            0x0013 => SimpleType::SQUAD,
            0x0023 => SimpleType::UQUAD,
            0x0076 => SimpleType::SINT64,
            0x0077 => SimpleType::UINT64,
            0x0014 => SimpleType::SOCTA,
            0x0024 => SimpleType::UOCTA,
            0x0078 => SimpleType::SINT128,
            0x0079 => SimpleType::UINT128,
            0x0046 => SimpleType::FLOAT16,
            0x0040 => SimpleType::FLOAT32,
            0x0045 => SimpleType::FLOAT32_PARTIAL_PRECISION,
            0x0044 => SimpleType::FLOAT48,
            0x0041 => SimpleType::FLOAT64,
            0x0042 => SimpleType::FLOAT80,
            0x0043 => SimpleType::FLOAT128,
            0x0056 => SimpleType::COMPLEX16,
            0x0050 => SimpleType::COMPLEX32,
            0x0055 => SimpleType::COMPLEX32_PARTIAL_PRECISION,
            0x0054 => SimpleType::COMPLEX48,
            0x0051 => SimpleType::COMPLEX64,
            0x0052 => SimpleType::COMPLEX80,
            0x0053 => SimpleType::COMPLEX128,
            0x0030 => SimpleType::BOOL8,
            0x0031 => SimpleType::BOOL16,
            0x0032 => SimpleType::BOOL32,
            0x0033 => SimpleType::BOOL64,
            0x0034 => SimpleType::BOOL128,
            _ => SimpleType::UNKNOWN(value),
        }
    }
}

impl From<SimpleType> for u32 {
    fn from(value: SimpleType) -> u32 {
        match value {
            SimpleType::VOID => 0x0003,
            SimpleType::SCHAR => 0x0010,
            SimpleType::UCHAR => 0x0020,
            SimpleType::RCHAR => 0x0070,
            SimpleType::WCHAR => 0x0071,
            SimpleType::CHAR16 => 0x007a,
            SimpleType::CHAR32 => 0x007b,
            SimpleType::CHAR8 => 0x007c,
            SimpleType::SBYTE => 0x0068,
            SimpleType::UBYTE => 0x0069,
            SimpleType::SSHORT => 0x0011,
            SimpleType::USHORT => 0x0021,
            SimpleType::SINT16 => 0x0072,
            SimpleType::UINT16 => 0x0073,
            SimpleType::SLONG => 0x0012,
            SimpleType::ULONG => 0x0022,
            SimpleType::SINT32 => 0x0074,
            SimpleType::UINT32 => 0x0075,
            SimpleType::SQUAD => 0x0013,
            SimpleType::UQUAD => 0x0023,
            SimpleType::SINT64 => 0x0076,
            SimpleType::UINT64 => 0x0077,
            SimpleType::SOCTA => 0x0014,
            SimpleType::UOCTA => 0x0024,
            SimpleType::SINT128 => 0x0078,
            SimpleType::UINT128 => 0x0079,
            SimpleType::FLOAT16 => 0x0046,
            SimpleType::FLOAT32 => 0x0040,
            SimpleType::FLOAT32_PARTIAL_PRECISION => 0x0045,
            SimpleType::FLOAT48 => 0x0044,
            SimpleType::FLOAT64 => 0x0041,
            SimpleType::FLOAT80 => 0x0042,
            SimpleType::FLOAT128 => 0x0043,
            SimpleType::COMPLEX16 => 0x0056,
            SimpleType::COMPLEX32 => 0x0050,
            SimpleType::COMPLEX32_PARTIAL_PRECISION => 0x0055,
            SimpleType::COMPLEX48 => 0x0054,
            SimpleType::COMPLEX64 => 0x0051,
            SimpleType::COMPLEX80 => 0x0052,
            SimpleType::COMPLEX128 => 0x0053,
            SimpleType::BOOL8 => 0x0030,
            SimpleType::BOOL16 => 0x0031,
            SimpleType::BOOL32 => 0x0032,
            SimpleType::BOOL64 => 0x0033,
            SimpleType::BOOL128 => 0x0034,
            SimpleType::UNKNOWN(v) => v,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SimpleMode {
    /// Not a pointer (direct access)
    DIRECT,
    /// Far pointer
    FAR_POINTER,
    /// Huge pointer
    HUGE_POINTER,
    /// 32-bit Near pointer
    NEAR_POINTER32,
    /// 32-bit Far pointer
    FAR_POINTER32,
    /// 64-bit Near pointer
    NEAR_POINTER64,
    /// 128-bit Near pointer
    NEAR_POINTER128,

    UNKNOWN(u32),
}

impl From<u32> for SimpleMode {
    fn from(value: u32) -> Self {
        match value {
            0x00000000 => SimpleMode::DIRECT,
            0x00000200 => SimpleMode::FAR_POINTER,
            0x00000300 => SimpleMode::HUGE_POINTER,
            0x00000400 => SimpleMode::NEAR_POINTER32,
            0x00000500 => SimpleMode::FAR_POINTER32,
            0x00000600 => SimpleMode::NEAR_POINTER64,
            0x00000700 => SimpleMode::NEAR_POINTER128,
            _ => SimpleMode::UNKNOWN(value),
        }
    }
}

impl From<SimpleMode> for u32 {
    fn from(value: SimpleMode) -> u32 {
        match value {
            SimpleMode::DIRECT => 0x00000000,
            SimpleMode::FAR_POINTER => 0x00000200,
            SimpleMode::HUGE_POINTER => 0x00000300,
            SimpleMode::NEAR_POINTER32 => 0x00000400,
            SimpleMode::FAR_POINTER32 => 0x00000500,
            SimpleMode::NEAR_POINTER64 => 0x00000600,
            SimpleMode::NEAR_POINTER128 => 0x00000700,
            SimpleMode::UNKNOWN(v) => v,
        }
    }
}

impl Simple<'_> {
    /// Check if this simple type is a pointer.
    pub fn is_pointer(&self) -> bool {
        self.ptr.is_pointer()
    }

    /// Check if the underlying type is signed
    pub fn is_signed(&self) -> bool {
        self.ptr.is_signed()
    }

    /// Returns the underlying primitive type.
    pub fn get_type(&self) -> SimpleType {
        SimpleType::from(self.ptr.get_type())
    }

    /// Returns the mode (pointer type) of this Simple type.
    pub fn modes(&self) -> SimpleMode {
        SimpleMode::from(self.ptr.modes())
    }
}

impl PdbType for Simple<'_> {
    fn get_base(&self) -> &ffi::PDB_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
