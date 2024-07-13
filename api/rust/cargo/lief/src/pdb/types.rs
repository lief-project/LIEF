use lief_ffi as ffi;

use crate::{common::FromFFI, Error};

use crate::to_conv_result;
use std::marker::PhantomData;
use crate::debug_location::DebugLocation;
use crate::common::into_optional;
use crate::declare_fwd_iterator;

pub mod simple;
pub mod array;
pub mod bitfield;
pub mod classlike;
pub mod enum_ty;
pub mod function;
pub mod modifier;
pub mod pointer;
pub mod union;
pub mod attribute;
pub mod method;

#[doc(inline)]
pub use simple::Simple;

#[doc(inline)]
pub use array::Array;

#[doc(inline)]
pub use bitfield::BitField;

#[doc(inline)]
pub use classlike::{Class, Structure, Interface};

#[doc(inline)]
pub use enum_ty::Enum;

#[doc(inline)]
pub use function::Function;

#[doc(inline)]
pub use modifier::Modifier;

#[doc(inline)]
pub use pointer::Pointer;

#[doc(inline)]
pub use union::Union;

#[doc(inline)]
pub use attribute::Attribute;

#[doc(inline)]
pub use method::Method;

pub enum Type<'a> {
    /// Represent primitive types (int, float, ...)
    Simple(Simple<'a>),

    /// Mirror `LF_ARRAY`
    Array(Array<'a>),

    /// Mirror `LF_BITFIELD
    BitField(BitField<'a>),

    /// Mirror `LF_CLASS
    Class(Class<'a>),

    /// Mirror `LF_STRUCTURE
    Structure(Structure<'a>),

    /// Mirror `LF_INTERFACE
    Interface(Interface<'a>),

    /// Mirror `LF_ENUM
    Enum(Enum<'a>),

    /// Mirror `LF_PROCEDURE
    Function(Function<'a>),

    /// Mirror `LF_MODIFIER
    Modifier(Modifier<'a>),

    /// Mirror `LF_POINTER
    Pointer(Pointer<'a>),

    /// Mirror `LF_UNION
    Union(Union<'a>),

    Generic(Generic<'a>),
}

impl FromFFI<ffi::PDB_Type> for Type<'_> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::PDB_Type>) -> Self {
        unsafe {
            let type_ref = ffi_entry.as_ref().unwrap();

            if ffi::PDB_types_Simple::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PDB_Type>;
                    type To = cxx::UniquePtr<ffi::PDB_types_Simple>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Simple(Simple::from_ffi(raw))
            } else if ffi::PDB_types_Array::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PDB_Type>;
                    type To = cxx::UniquePtr<ffi::PDB_types_Array>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Array(Array::from_ffi(raw))
            } else if ffi::PDB_types_BitField::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PDB_Type>;
                    type To = cxx::UniquePtr<ffi::PDB_types_BitField>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::BitField(BitField::from_ffi(raw))
            } else if ffi::PDB_types_Class::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PDB_Type>;
                    type To = cxx::UniquePtr<ffi::PDB_types_Class>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Class(Class::from_ffi(raw))
            } else if ffi::PDB_types_Structure::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PDB_Type>;
                    type To = cxx::UniquePtr<ffi::PDB_types_Structure>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Structure(Structure::from_ffi(raw))
            } else if ffi::PDB_types_Interface::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PDB_Type>;
                    type To = cxx::UniquePtr<ffi::PDB_types_Interface>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Interface(Interface::from_ffi(raw))
            } else if ffi::PDB_types_Enum::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PDB_Type>;
                    type To = cxx::UniquePtr<ffi::PDB_types_Enum>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Enum(Enum::from_ffi(raw))
            } else if ffi::PDB_types_Function::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PDB_Type>;
                    type To = cxx::UniquePtr<ffi::PDB_types_Function>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Function(Function::from_ffi(raw))
            } else if ffi::PDB_types_Modifier::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PDB_Type>;
                    type To = cxx::UniquePtr<ffi::PDB_types_Modifier>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Modifier(Modifier::from_ffi(raw))
            } else if ffi::PDB_types_Pointer::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PDB_Type>;
                    type To = cxx::UniquePtr<ffi::PDB_types_Pointer>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Pointer(Pointer::from_ffi(raw))
            } else if ffi::PDB_types_Union::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PDB_Type>;
                    type To = cxx::UniquePtr<ffi::PDB_types_Union>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Union(Union::from_ffi(raw))
            } else {
                Type::Generic(Generic::from_ffi(ffi_entry))
            }
        }
    }
}

pub struct Generic<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_Type>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::PDB_Type> for Generic<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::PDB_Type>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

pub trait PdbType {
    #[doc(hidden)]
    fn get_base(&self) -> &ffi::PDB_Type;
}

impl PdbType for Type<'_> {
    fn get_base(&self) -> &ffi::PDB_Type {
        match &self {
            Type::Simple(ty) => {
                ty.get_base()
            }
            Type::Array(ty) => {
                ty.get_base()
            }
            Type::BitField(ty) => {
                ty.get_base()
            }
            Type::Class(ty) => {
                ty.get_base()
            }
            Type::Structure(ty) => {
                ty.get_base()
            }
            Type::Interface(ty) => {
                ty.get_base()
            }
            Type::Enum(ty) => {
                ty.get_base()
            }
            Type::Function(ty) => {
                ty.get_base()
            }
            Type::Modifier(ty) => {
                ty.get_base()
            }
            Type::Pointer(ty) => {
                ty.get_base()
            }
            Type::Union(ty) => {
                ty.get_base()
            }
            Type::Generic(ty) => {
                ty.get_base()
            }
        }
    }
}

impl PdbType for Generic<'_> {
    fn get_base(&self) -> &ffi::PDB_Type {
        self.ptr.as_ref().unwrap()
    }
}

declare_fwd_iterator!(
    Types,
    Type<'a>,
    ffi::PDB_Type,
    ffi::PDB_DebugInfo,
    ffi::PDB_DebugInfo_it_types
);

