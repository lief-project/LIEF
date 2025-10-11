use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::dwarf::editor::types::EditorType;

/// This structure represents an editable enum type (`DW_TAG_enumeration_type`)
pub struct Enum {
    ptr: cxx::UniquePtr<ffi::DWARF_editor_EnumType>,
}

impl FromFFI<ffi::DWARF_editor_EnumType> for Enum {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_editor_EnumType>) -> Self {
        Self {
            ptr: cmd,
        }
    }
}

impl Enum {
    /// Define the number of bytes required to hold an instance of the
    /// enumeration (`DW_AT_byte_size`).
    pub fn set_size(&mut self, size: u64) {
        self.ptr.pin_mut().set_size(size);
    }

    /// Add an enum value by specifying its name and its integer value
    pub fn add_value(&mut self, name: &str, value: i64) -> Value {
        Value::from_ffi(self.ptr.pin_mut().add_value(name, value))
    }

    /// Set the underlying type that is used to encode this enum
    pub fn set_underlying_type(&mut self, ty: &dyn EditorType) -> &mut Self {
        self.ptr.pin_mut().set_underlying_type(ty.get_base());
        self
    }
}


impl EditorType for Enum {
    fn get_base(&self) -> &ffi::DWARF_editor_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}


/// This structure represents an enum value.
#[allow(dead_code)]
pub struct Value {
    ptr: cxx::UniquePtr<ffi::DWARF_editor_EnumType_Value>,
}

impl FromFFI<ffi::DWARF_editor_EnumType_Value> for Value {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_editor_EnumType_Value>) -> Self {
        Self {
            ptr: cmd,
        }
    }
}
