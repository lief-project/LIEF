use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::dwarf::editor::types::EditorType;

/// This structure represents a function type (`DW_TAG_subroutine_type`)
pub struct Function {
    ptr: cxx::UniquePtr<ffi::DWARF_editor_FunctionType>,
}

impl FromFFI<ffi::DWARF_editor_FunctionType> for Function {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_editor_FunctionType>) -> Self {
        Self {
            ptr: cmd,
        }
    }
}

impl EditorType for Function {
    fn get_base(&self) -> &ffi::DWARF_editor_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl Function {
    /// Set the return type of this function
    pub fn set_return_type(&mut self, ty: &dyn EditorType) -> &mut Self {
        self.ptr.pin_mut().set_return_type(ty.get_base());
        self
    }

    /// Add a parameter
    pub fn add_parameter(&mut self, ty: &dyn EditorType) -> Parameter {
        Parameter::from_ffi(self.ptr.pin_mut().add_parameter(ty.get_base()))
    }
}

/// This structure represents a function's parameter
#[allow(dead_code)]
pub struct Parameter {
    ptr: cxx::UniquePtr<ffi::DWARF_editor_FunctionType_Parameter>,
}

impl FromFFI<ffi::DWARF_editor_FunctionType_Parameter> for Parameter {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_editor_FunctionType_Parameter>) -> Self {
        Self {
            ptr: cmd,
        }
    }
}


