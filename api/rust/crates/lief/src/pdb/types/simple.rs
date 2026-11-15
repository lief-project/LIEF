use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::enum_from_int;
use crate::pdb::types::PdbType;
use std::marker::PhantomData;

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

enum_from_int! {
    #[allow(non_camel_case_types)]
    SimpleType: u32 {
        /// Void type (return type or void*)
        VOID = 0x0003,

        // --- Characters ---
        /// Signed Character
        SCHAR = 0x0010,
        /// Unsigned Character
        UCHAR = 0x0020,
        /// "Real" Character (char)
        RCHAR = 0x0070,

        // --- Unicode / Wide Characters ---
        /// Wide Character (wchar_t)
        WCHAR = 0x0071,
        /// 16-bit Character (char16_t)
        CHAR16 = 0x007a,
        /// 32-bit Character (char32_t)
        CHAR32 = 0x007b,
        /// 8-bit Character (char8_t)
        CHAR8 = 0x007c,

        // --- Bytes ---
        /// Signed Byte
        SBYTE = 0x0068,
        /// Unsigned Byte
        UBYTE = 0x0069,

        // --- Short (16-bit) ---
        /// Signed Short
        SSHORT = 0x0011,
        /// Unsigned Short
        USHORT = 0x0021,

        /// Explicit Signed 16-bit Integer
        SINT16 = 0x0072,
        /// Explicit Unsigned 16-bit Integer
        UINT16 = 0x0073,

        // --- Long (32-bit) ---
        /// Signed Long
        SLONG = 0x0012,
        /// Unsigned Long
        ULONG = 0x0022,

        /// Explicit Signed 32-bit Integer
        SINT32 = 0x0074,
        /// Explicit Unsigned 32-bit Integer
        UINT32 = 0x0075,

        // --- Quad (64-bit) ---
        /// Signed Quadword
        SQUAD = 0x0013,
        /// Unsigned Quadword
        UQUAD = 0x0023,

        /// Explicit Signed 64-bit Integer
        SINT64 = 0x0076,
        /// Explicit Unsigned 64-bit Integer
        UINT64 = 0x0077,

        // --- Octa (128-bit) ---
        /// Signed Octaword
        SOCTA = 0x0014,
        /// Unsigned Octaword
        UOCTA = 0x0024,

        /// Explicit Signed 128-bit Integer
        SINT128 = 0x0078,
        /// Explicit Unsigned 128-bit Integer
        UINT128 = 0x0079,

        // --- Floating Point ---
        /// 16-bit Floating point
        FLOAT16 = 0x0046,
        /// 32-bit Floating point (float)
        FLOAT32 = 0x0040,
        FLOAT32_PARTIAL_PRECISION = 0x0045,

        /// 48-bit Floating point
        FLOAT48 = 0x0044,
        /// 64-bit Floating point (double)
        FLOAT64 = 0x0041,
        /// 80-bit Floating point
        FLOAT80 = 0x0042,
        /// 128-bit Floating point
        FLOAT128 = 0x0043,

        // --- Complex Numbers ---
        COMPLEX16 = 0x0056,
        COMPLEX32 = 0x0050,
        COMPLEX32_PARTIAL_PRECISION = 0x0055,
        COMPLEX48 = 0x0054,
        COMPLEX64 = 0x0051,
        COMPLEX80 = 0x0052,
        COMPLEX128 = 0x0053,

        // --- Booleans ---
        /// 8-bit Boolean
        BOOL8 = 0x0030,
        /// 16-bit Boolean
        BOOL16 = 0x0031,
        /// 32-bit Boolean
        BOOL32 = 0x0032,
        /// 64-bit Boolean
        BOOL64 = 0x0033,
        /// 128-bit Boolean
        BOOL128 = 0x0034,
    }
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    SimpleMode: u32 {
        /// Not a pointer (direct access)
        DIRECT = 0x00000000,
        /// Far pointer
        FAR_POINTER = 0x00000200,
        /// Huge pointer
        HUGE_POINTER = 0x00000300,
        /// 32-bit Near pointer
        NEAR_POINTER32 = 0x00000400,
        /// 32-bit Far pointer
        FAR_POINTER32 = 0x00000500,
        /// 64-bit Near pointer
        NEAR_POINTER64 = 0x00000600,
        /// 128-bit Near pointer
        NEAR_POINTER128 = 0x00000700,
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
