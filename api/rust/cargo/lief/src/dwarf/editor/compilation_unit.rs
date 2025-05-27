use lief_ffi as ffi;

use std::option::Option;
use std::marker::PhantomData;
use crate::{common::FromFFI, common::into_optional};

use super::function::Function;
use super::types::{Array, Base, EditorType, Enum, Pointer, Struct, Typedef};
use super::types::Function as FunctionType;
use super::types::struct_ty;
use super::types::base;
use super::variable::Variable;
use super::Type;

/// This structure represents an **editable** DWARF compilation unit
pub struct CompilationUnit<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_editor_CompilationUnit>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_editor_CompilationUnit> for CompilationUnit<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_editor_CompilationUnit>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl CompilationUnit<'_> {
    /// Set the `DW_AT_producer` producer attribute.
    ///
    /// This attribute aims to inform about the program that generated this
    /// compilation unit (e.g. `LIEF Extended`)
    pub fn set_producer(&mut self, value: &str) {
        self.ptr.pin_mut().set_producer(value)
    }

    /// Create a new function owned by this compilation unit
    pub fn create_function(&mut self, name: &str) -> Option<Function> {
        into_optional(self.ptr.pin_mut().create_function(name))
    }

    /// Create a new **global** variable owned by this compilation unit
    pub fn create_variable(&mut self, name: &str) -> Option<Variable> {
        into_optional(self.ptr.pin_mut().create_variable(name))
    }

    /// Create a `DW_TAG_unspecified_type` type with the given name
    pub fn create_generic_type(&mut self, name: &str) -> Type {
        Type::from_ffi(self.ptr.pin_mut().create_generic_type(name))
    }

    /// Create an enum type (`DW_TAG_enumeration_type`)
    pub fn create_enum(&mut self, name: &str) -> Enum {
        Enum::from_ffi(self.ptr.pin_mut().create_enum(name))
    }

    /// Create a typdef with the name provided in the first parameter which aliases
    /// the type provided in the second parameter
    pub fn create_typedef(&mut self, name: &str, ty: &dyn EditorType) -> Typedef {
        Typedef::from_ffi(self.ptr.pin_mut().create_typedef(name, ty.get_base()))
    }

    /// Create a structure type (`DW_TAG_structure_type`)
    pub fn create_structure(&mut self, name: &str) -> Struct {
        Struct::from_ffi(self.ptr.pin_mut().create_structure(name, struct_ty::Kind::STRUCT.into()))
    }

    /// Create a structure type (`DW_TAG_class_type`)
    pub fn create_class(&mut self, name: &str) -> Struct {
        Struct::from_ffi(self.ptr.pin_mut().create_structure(name, struct_ty::Kind::CLASS.into()))
    }

    /// Create a union type (`DW_TAG_union_type`)
    pub fn create_union(&mut self, name: &str) -> Struct {
        Struct::from_ffi(self.ptr.pin_mut().create_structure(name, struct_ty::Kind::UNION.into()))
    }

    /// Create a primitive type with the given name and size.
    pub fn create_base_type(&mut self, name: &str, size: u64, encoding: base::Encoding) -> Base {
        Base::from_ffi(self.ptr.pin_mut().create_base_type(name, size, encoding.into()))
    }

    /// Create a function type with the given name.
    pub fn create_function_type(&mut self, name: &str) -> FunctionType {
        FunctionType::from_ffi(self.ptr.pin_mut().create_function_type(name))
    }

    /// Create a pointer on the provided type
    pub fn create_pointer_type(&mut self, ty: &dyn EditorType) -> Pointer {
        Pointer::from_ffi(self.ptr.pin_mut().create_pointer_type(ty.get_base()))
    }

    /// Create a `void` type
    pub fn create_void_type(&mut self) -> Type {
        Type::from_ffi(self.ptr.pin_mut().create_void_type())
    }

    /// Create an array type with the given name, type and size.
    pub fn create_array_type(&mut self, name: &str, ty:&dyn EditorType, count: u64) -> Array {
        Array::from_ffi(self.ptr.pin_mut().create_array_type(name, ty.get_base(), count))
    }
}
