use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::dwarf::editor::types::EditorType;

/// This structure represents a `DW_TAG_pointer_type` DWARF type.
pub struct Pointer {
    ptr: cxx::UniquePtr<ffi::DWARF_editor_PointerType>,
}

impl FromFFI<ffi::DWARF_editor_PointerType> for Pointer {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_editor_PointerType>) -> Self {
        Self {
            ptr: cmd,
        }
    }
}


impl EditorType for Pointer {
    fn get_base(&self) -> &ffi::DWARF_editor_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

