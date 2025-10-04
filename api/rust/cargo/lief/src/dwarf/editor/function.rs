use lief_ffi as ffi;


use crate::common::{FromFFI, into_optional};

use crate::dwarf::editor::types::EditorType;
use crate::dwarf::editor::Variable;

/// This structure represents an **editable** DWARF function (`DW_TAG_subprogram`)
pub struct Function {
    ptr: cxx::UniquePtr<ffi::DWARF_editor_Function>,
}

impl FromFFI<ffi::DWARF_editor_Function> for Function {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_editor_Function>) -> Self {
        Self {
            ptr,
        }
    }
}

/// This structure defines an implementation range
pub struct Range {
    start: u64,
    end: u64,
}


/// This structure represents a parameter of the current function (`DW_TAG_formal_parameter`)
pub struct Parameter {
    ptr: cxx::UniquePtr<ffi::DWARF_editor_Function_Parameter>,
}

impl Parameter {
    /// Assign this parameter to a specific named register.
    pub fn assign_register_by_name(&mut self, name: &str) -> &mut Self {
        self.ptr.pin_mut().assign_register_by_name(name);
        self
    }

    /// Assign this parameter to the given DWARF register id (e.g. `DW_OP_reg0`).
    pub fn assign_register_by_id(&mut self, id: u64) -> &mut Self {
        self.ptr.pin_mut().assign_register_by_id(id);
        self
    }
}

impl FromFFI<ffi::DWARF_editor_Function_Parameter> for Parameter {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_editor_Function_Parameter>) -> Self {
        Self {
            ptr,
        }
    }
}

/// This structure mirrors the `DW_TAG_lexical_block` DWARF tag
pub struct LexicalBlock {
    ptr: cxx::UniquePtr<ffi::DWARF_editor_Function_LexicalBlock>,
}

impl FromFFI<ffi::DWARF_editor_Function_LexicalBlock> for LexicalBlock {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_editor_Function_LexicalBlock>) -> Self {
        Self {
            ptr,
        }
    }
}

impl LexicalBlock {
    /// Create a `DW_AT_name` entry to associate a name to this entry
    pub fn add_name(&mut self, name: &str) -> &mut Self {
        self.ptr.pin_mut().add_name(name);
        self
    }

    /// Create a `DW_AT_description` entry with the description
    /// provided in parameter.
    pub fn add_description(&mut self, description: &str) -> &mut Self {
        self.ptr.pin_mut().add_description(description);
        self
    }

    /// Create a sub-block with the given low/high addresses.
    pub fn add_block(&mut self, start: u64, end: u64) -> Option<LexicalBlock> {
        into_optional(self.ptr.pin_mut().add_block(start, end))
    }

    /// Create a sub-block with the given range of addresses.
    pub fn add_block_from_range(&mut self, ranges: &[Range]) -> Option<LexicalBlock> {
        let mut ffi_ranges = cxx::CxxVector::new();
        for range in ranges {
            let ffi_range = ffi::DWARF_editor_Function_Range {
                start: range.start,
                end: range.end,
            };
            ffi_ranges.as_mut().unwrap().push(ffi_range);
        }
        into_optional(self.ptr.pin_mut().add_block_from_range(&ffi_ranges))
    }
}

/// This class mirrors the `DW_TAG_label` DWARF tag
#[allow(dead_code)]
pub struct Label {
    ptr: cxx::UniquePtr<ffi::DWARF_editor_Function_Label>,
}

impl FromFFI<ffi::DWARF_editor_Function_Label> for Label {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_editor_Function_Label>) -> Self {
        Self {
            ptr,
        }
    }
}

impl Function {
    /// Set the address of this function by defining `DW_AT_entry_pc`
    pub fn set_address(&mut self, addr: u64) -> &mut Self {
        self.ptr.pin_mut().set_address(addr);
        self
    }

    /// Set the upper and lower bound addresses for this function. This assumes
    /// that the function is contiguous between `low` and `high`.
    ///
    /// Underneath, the function defines `DW_AT_low_pc` and `DW_AT_high_pc`
    pub fn set_low_high(&mut self, low: u64, high: u64) -> &mut Self {
        self.ptr.pin_mut().set_low_high(low, high);
        self
    }

    /// Set the ranges of addresses owned by the implementation of this function
    /// by setting the `DW_AT_ranges` attribute.
    ///
    /// This setter should be used for non-contiguous function.
    pub fn set_ranges(&mut self, ranges: &[Range]) -> &mut Self {
        let mut ffi_ranges = cxx::CxxVector::new();
        for range in ranges {
            let ffi_range = ffi::DWARF_editor_Function_Range {
                start: range.start,
                end: range.end,
            };
            ffi_ranges.as_mut().unwrap().push(ffi_range);
        }
        self.ptr.pin_mut().set_ranges(&ffi_ranges);
        self
    }

    /// Set the function as external by defining `DW_AT_external` to true.
    /// This means that the function is **imported** by the current compilation unit.
    pub fn set_external(&mut self) -> &mut Self {
        self.ptr.pin_mut().set_external();
        self
    }

    /// Set the return type of this function
    pub fn set_return_type(&mut self, ty: &dyn EditorType) -> &mut Self {
        self.ptr.pin_mut().set_return_type(ty.get_base());
        self
    }

    /// Add a parameter to the current function
    pub fn add_parameter(&mut self, name: &str, ty: &dyn EditorType) -> Parameter {
        Parameter::from_ffi(self.ptr.pin_mut().add_parameter(name, ty.get_base()))
    }

    /// Create a stack-based variable owned by the current function
    pub fn create_stack_variable(&mut self, name: &str) -> Variable {
        Variable::from_ffi(self.ptr.pin_mut().create_stack_variable(name))
    }

    /// Add a lexical block with the given range
    pub fn add_lexical_block(&mut self, start: u64, end: u64) -> LexicalBlock {
        LexicalBlock::from_ffi(self.ptr.pin_mut().add_lexical_block(start, end))
    }

    /// Add a label at the given address
    pub fn add_label(&mut self, addr: u64, name: &str) -> Label {
        Label::from_ffi(self.ptr.pin_mut().add_label(addr, name))
    }

    /// Create a `DW_AT_description` entry with the description
    /// provided in parameter.
    pub fn add_description(&mut self, description: &str) -> &mut Self {
        self.ptr.pin_mut().add_description(description);
        self
    }
}
