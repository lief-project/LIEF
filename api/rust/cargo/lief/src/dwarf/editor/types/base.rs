use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::dwarf::editor::types::EditorType;

/// This structure represents a primitive type like `int, char`.
pub struct Base {
    ptr: cxx::UniquePtr<ffi::DWARF_editor_BaseType>,
}


#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Encoding {
    NONE,
    ADDRESS,
    SIGNED,
    SIGNED_CHAR,
    UNSIGNED,
    UNSIGNED_CHAR,
    BOOLEAN,
    FLOAT,
    UNKNOWN(u32),
}

impl From<u32> for Encoding {
    fn from(value: u32) -> Self {
        match value {
            0x00000000 => Encoding::NONE,
            0x00000001 => Encoding::ADDRESS,
            0x00000002 => Encoding::SIGNED,
            0x00000003 => Encoding::SIGNED_CHAR,
            0x00000004 => Encoding::UNSIGNED,
            0x00000005 => Encoding::UNSIGNED_CHAR,
            0x00000006 => Encoding::BOOLEAN,
            0x00000007 => Encoding::FLOAT,
            _ => Encoding::UNKNOWN(value),

        }
    }
}


impl From<Encoding> for u32 {
    fn from(value: Encoding) -> Self {
        match value {
            Encoding::NONE => 0,
            Encoding::ADDRESS => 1,
            Encoding::SIGNED => 2,
            Encoding::SIGNED_CHAR => 3,
            Encoding::UNSIGNED => 4,
            Encoding::UNSIGNED_CHAR => 5,
            Encoding::BOOLEAN => 6,
            Encoding::FLOAT => 7,
            Encoding::UNKNOWN(value) => value,

        }
    }
}

impl FromFFI<ffi::DWARF_editor_BaseType> for Base {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_editor_BaseType>) -> Self {
        Self {
            ptr: cmd,
        }
    }
}


impl EditorType for Base {
    fn get_base(&self) -> &ffi::DWARF_editor_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

