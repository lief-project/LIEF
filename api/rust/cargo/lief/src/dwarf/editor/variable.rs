use lief_ffi as ffi;

use crate::common::FromFFI;

use crate::dwarf::editor::Type;
use crate::dwarf::editor::types::EditorType;

pub struct Variable {
    ptr: cxx::UniquePtr<ffi::DWARF_editor_Variable>,
}

impl FromFFI<ffi::DWARF_editor_Variable> for Variable {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_editor_Variable>) -> Self {
        Self {
            ptr,
        }
    }
}

impl Variable {
    /// Set the global address of this variable. Setting this address is only
    /// revelant in the case of a static global variable. For stack variable, you
    /// should use [`Variable::set_stack_offset`].
    ///
    /// This function set the `DW_AT_location` attribute
    pub fn set_addr(&mut self, addr: u64) -> &mut Self {
        self.ptr.pin_mut().set_addr(addr);
        self
    }

    /// Set the stack offset of this variable.
    ///
    /// This function set the `DW_AT_location` attribute
    pub fn set_stack_offset(&mut self, addr: u64) -> &mut Self {
        self.ptr.pin_mut().set_stack_offset(addr);
        self
    }

    /// Mark this variable as **imported**
    pub fn set_external(&mut self) -> &mut Self {
        self.ptr.pin_mut().set_external();
        self
    }

    /// Set the type of the current variable
    pub fn set_type(&mut self, ty: &Type) -> &mut Self {
        self.ptr.pin_mut().set_type(ty.get_base());
        self
    }

    /// Create a `DW_AT_description` entry with the description
    /// provided in parameter.
    pub fn add_description(&mut self, description: &str) -> &mut Self {
        self.ptr.pin_mut().add_description(description);
        self
    }
}
