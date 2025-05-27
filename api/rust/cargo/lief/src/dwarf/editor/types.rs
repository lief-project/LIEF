use lief_ffi as ffi;

pub mod pointer;
pub mod array;
pub mod base;
pub mod enum_ty;
pub mod function;
pub mod struct_ty;
pub mod typedef;

use crate::common::FromFFI;

#[doc(inline)]
pub use pointer::Pointer;

#[doc(inline)]
pub use array::Array;

#[doc(inline)]
pub use base::Base;

#[doc(inline)]
pub use enum_ty::Enum;

#[doc(inline)]
pub use function::Function;

#[doc(inline)]
pub use struct_ty::Struct;

#[doc(inline)]
pub use typedef::Typedef;

/// The different types supported by the editor interface
pub enum Type {
    /// Mirror `DW_TAG_pointer_type`
    Pointer(Pointer),

    /// Mirror `DW_TAG_array_type`
    Array(Array),

    /// Mirror `DW_TAG_base_type`
    Base(Base),

    /// Mirror `DW_TAG_enumeration_type`
    Enum(Enum),

    /// Mirror `DW_TAG_subroutine_type`
    Function(Function),

    /// Mirror `DW_TAG_class_type, DW_TAG_structure_type, DW_TAG_union_type`
    Struct(Struct),

    /// Mirror `DW_TAG_typedef`
    Typedef(Typedef),

    Generic(Generic),
}

impl FromFFI<ffi::DWARF_editor_Type> for Type {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::DWARF_editor_Type>) -> Self {
        unsafe {
            let type_ref = ffi_entry.as_ref().unwrap();

            if ffi::DWARF_editor_PointerType::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_editor_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_editor_PointerType>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Pointer(Pointer::from_ffi(raw))
            } else if ffi::DWARF_editor_ArrayType::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_editor_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_editor_ArrayType>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Array(Array::from_ffi(raw))
            } else if ffi::DWARF_editor_BaseType::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_editor_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_editor_BaseType>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Base(Base::from_ffi(raw))
            } else if ffi::DWARF_editor_EnumType::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_editor_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_editor_EnumType>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Enum(Enum::from_ffi(raw))
            } else if ffi::DWARF_editor_FunctionType::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_editor_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_editor_FunctionType>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Function(Function::from_ffi(raw))
            } else if ffi::DWARF_editor_StructType::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_editor_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_editor_StructType>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Struct(Struct::from_ffi(raw))
            } else if ffi::DWARF_editor_TypeDef::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_editor_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_editor_TypeDef>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Typedef(Typedef::from_ffi(raw))
            } else {
                Type::Generic(Generic::from_ffi(ffi_entry))
            }
        }
    }
}

/// Generic trait shared by all DWARF editor types
pub trait EditorType {
    #[doc(hidden)]
    fn get_base(&self) -> &ffi::DWARF_editor_Type;

    fn pointer_to(&self) -> Pointer {
        Pointer::from_ffi(self.get_base().pointer_to())
    }
}

/// This structure represents a generic type (like `DW_TAG_unspecified_type`)
pub struct Generic {
    ptr: cxx::UniquePtr<ffi::DWARF_editor_Type>,
}

impl FromFFI<ffi::DWARF_editor_Type> for Generic {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_editor_Type>) -> Self {
        Self {
            ptr: cmd,
        }
    }
}

impl EditorType for Generic {
    fn get_base(&self) -> &ffi::DWARF_editor_Type {
        self.ptr.as_ref().unwrap()
    }
}

impl EditorType for Type {
    fn get_base(&self) -> &ffi::DWARF_editor_Type {
        match &self {
            Type::Pointer(s) => {
                s.get_base()
            }
            Type::Array(s) => {
                s.get_base()
            }
            Type::Base(s) => {
                s.get_base()
            }
            Type::Enum(s) => {
                s.get_base()
            }
            Type::Function(s) => {
                s.get_base()
            }
            Type::Struct(s) => {
                s.get_base()
            }
            Type::Typedef(s) => {
                s.get_base()
            }
            Type::Generic(s) => {
                s.get_base()
            }
        }
    }
}

