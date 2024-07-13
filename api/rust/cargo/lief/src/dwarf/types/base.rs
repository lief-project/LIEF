use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;
use crate::dwarf::types::DwarfType;

/// This class wraps the `DW_TAG_base_type` type which can be used -- for
/// instance -- to represent integers or primitive types.
pub struct Base<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_Base>,
    _owner: PhantomData<&'a ()>,
}


#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Encoding {
    NONE,

    /// Mirror `DW_ATE_signed`
    SIGNED,

    /// Mirror `DW_ATE_signed_char`
    SIGNED_CHAR,

    /// Mirror `DW_ATE_unsigned`
    UNSIGNED,

    /// Mirror `DW_ATE_unsigned_char`
    UNSIGNED_CHAR,

    /// Mirror `DW_ATE_float`
    FLOAT,

    /// Mirror `DW_ATE_boolean`
    BOOLEAN,

    /// Mirror `DW_ATE_address`
    ADDRESS,

    UNKNOWN(u32),
}

impl From<u32> for Encoding {
    fn from(value: u32) -> Self {
        match value {
            0x00000000 => Encoding::NONE,
            0x00000001 => Encoding::SIGNED,
            0x00000002 => Encoding::SIGNED_CHAR,
            0x00000003 => Encoding::UNSIGNED,
            0x00000004 => Encoding::UNSIGNED_CHAR,
            0x00000005 => Encoding::FLOAT,
            0x00000006 => Encoding::BOOLEAN,
            0x00000007 => Encoding::ADDRESS,
            _ => Encoding::UNKNOWN(value),

        }
    }
}
impl From<Encoding> for u32 {
    fn from(value: Encoding) -> u32 {
        match value {
            Encoding::NONE => 0x00000000,
            Encoding::SIGNED => 0x00000001,
            Encoding::SIGNED_CHAR => 0x00000002,
            Encoding::UNSIGNED => 0x00000003,
            Encoding::UNSIGNED_CHAR => 0x00000004,
            Encoding::FLOAT => 0x00000005,
            Encoding::BOOLEAN => 0x00000006,
            Encoding::ADDRESS => 0x00000007,
            Encoding::UNKNOWN(_) => 0,

        }
    }
}

impl FromFFI<ffi::DWARF_types_Base> for Base<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_types_Base>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Base<'_> {
    /// Describe how the the base type is encoded and should be interpreted
    pub fn encoding(&self) -> Encoding {
        Encoding::from(self.ptr.encoding())
    }
}

impl DwarfType for Base<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
