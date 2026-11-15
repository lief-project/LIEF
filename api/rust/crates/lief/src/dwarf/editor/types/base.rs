use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::dwarf::editor::types::EditorType;
use crate::enum_from_int;

/// This structure represents a primitive type like `int, char`.
pub struct Base {
    ptr: cxx::UniquePtr<ffi::DWARF_editor_BaseType>,
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    Encoding: u32 {
        NONE = 0x00000000,
        ADDRESS = 0x00000001,
        SIGNED = 0x00000002,
        SIGNED_CHAR = 0x00000003,
        UNSIGNED = 0x00000004,
        UNSIGNED_CHAR = 0x00000005,
        BOOLEAN = 0x00000006,
        FLOAT = 0x00000007,
    }
}

impl FromFFI<ffi::DWARF_editor_BaseType> for Base {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_editor_BaseType>) -> Self {
        Self { ptr: cmd }
    }
}

impl EditorType for Base {
    fn get_base(&self) -> &ffi::DWARF_editor_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
