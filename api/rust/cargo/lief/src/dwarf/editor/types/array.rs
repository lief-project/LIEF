use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::dwarf::editor::types::EditorType;

/// This structure represents an array type (`DW_TAG_array_type`).
pub struct Array {
    ptr: cxx::UniquePtr<ffi::DWARF_editor_ArrayType>,
}

impl FromFFI<ffi::DWARF_editor_ArrayType> for Array {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_editor_ArrayType>) -> Self {
        Self {
            ptr: cmd,
        }
    }
}

impl EditorType for Array {
    fn get_base(&self) -> &ffi::DWARF_editor_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

