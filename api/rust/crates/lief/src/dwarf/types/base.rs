use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::dwarf::types::DwarfType;
use crate::enum_from_int;
use std::marker::PhantomData;

/// This class wraps the `DW_TAG_base_type` type which can be used -- for
/// instance -- to represent integers or primitive types.
pub struct Base<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_Base>,
    _owner: PhantomData<&'a ()>,
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    Encoding: u32 {
        NONE = 0x00000000,

        /// Mirror `DW_ATE_signed`
        SIGNED = 0x00000001,

        /// Mirror `DW_ATE_signed_char`
        SIGNED_CHAR = 0x00000002,

        /// Mirror `DW_ATE_unsigned`
        UNSIGNED = 0x00000003,

        /// Mirror `DW_ATE_unsigned_char`
        UNSIGNED_CHAR = 0x00000004,

        /// Mirror `DW_ATE_float`
        FLOAT = 0x00000005,

        /// Mirror `DW_ATE_boolean`
        BOOLEAN = 0x00000006,

        /// Mirror `DW_ATE_address`
        ADDRESS = 0x00000007,
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
    /// Describe how the base type is encoded and should be interpreted
    pub fn encoding(&self) -> Encoding {
        Encoding::from(self.ptr.encoding())
    }
}

impl DwarfType for Base<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
