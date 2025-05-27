use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::dwarf::editor::types::EditorType;

/// This structure represents a typedef (`DW_TAG_typedef`).
pub struct Typedef {
    ptr: cxx::UniquePtr<ffi::DWARF_editor_TypeDef>,
}

impl FromFFI<ffi::DWARF_editor_TypeDef> for Typedef {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_editor_TypeDef>) -> Self {
        Self {
            ptr: cmd,
        }
    }
}


impl EditorType for Typedef {
    fn get_base(&self) -> &ffi::DWARF_editor_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

