use lief_ffi as ffi;

use crate::{common::FromFFI, Error};

use crate::to_conv_result;
use std::marker::PhantomData;
use crate::debug_location::DebugLocation;
use crate::dwarf::Scope;
use crate::common::into_optional;
use crate::declare_fwd_iterator;

pub mod classlike;
pub mod pointer;
pub mod const_ty;
pub mod base;
pub mod array;

#[doc(inline)]
pub use classlike::Structure;

#[doc(inline)]
pub use classlike::Class;

#[doc(inline)]
pub use classlike::Union;

#[doc(inline)]
pub use classlike::ClassLike;

#[doc(inline)]
pub use pointer::Pointer;

#[doc(inline)]
pub use const_ty::Const;

#[doc(inline)]
pub use base::Base;

#[doc(inline)]
pub use array::Array;

/// This class represents a DWARF Type which includes:
///
/// - `DW_TAG_array_type`
/// - `DW_TAG_const_type`
/// - `DW_TAG_pointer_type`
/// - `DW_TAG_structure_type`
/// - `DW_TAG_base_type`
/// - `DW_TAG_class_type`
/// - `DW_TAG_enumeration_type`
/// - `DW_TAG_string_type`
/// - `DW_TAG_union_type`
/// - `DW_TAG_volatile_type`
/// - `DW_TAG_unspecified_type`
pub enum Type<'a> {
    /// Interface over `DW_TAG_structure_type`
    Structure(Structure<'a>),

    /// Interface over `DW_TAG_class_type`
    Class(Class<'a>),

    /// Interface over `DW_TAG_union_type`
    Union(Union<'a>),

    /// Interface over `DW_TAG_pointer_type`
    Pointer(Pointer<'a>),

    /// Interface over `DW_TAG_const_type`
    Const(Const<'a>),

    /// Interface over `DW_TAG_base_type`
    Base(Base<'a>),

    /// Interface over `DW_TAG_array_type`
    Array(Array<'a>),

    /// Generic type (fallback value)
    Generic(Generic<'a>),
}

impl FromFFI<ffi::DWARF_Type> for Type<'_> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::DWARF_Type>) -> Self {
        unsafe {
            let type_ref = ffi_entry.as_ref().unwrap();

            if ffi::DWARF_types_Structure::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_Structure>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Structure(Structure::from_ffi(raw))
            } else if ffi::DWARF_types_Class::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_Class>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Class(Class::from_ffi(raw))
            } else if ffi::DWARF_types_Union::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_Union>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Union(Union::from_ffi(raw))
            } else if ffi::DWARF_types_Pointer::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_Pointer>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Pointer(Pointer::from_ffi(raw))
            } else if ffi::DWARF_types_Const::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_Const>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Const(Const::from_ffi(raw))
            } else if ffi::DWARF_types_Base::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_Base>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Base(Base::from_ffi(raw))
            } else if ffi::DWARF_types_Array::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_Array>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Array(Array::from_ffi(raw))
            } else {
                Type::Generic(Generic::from_ffi(ffi_entry))
            }
        }
    }
}

/// Generic structure for types that do not required a dedicated interface
pub struct Generic<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_Type>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_Type> for Generic<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_Type>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

/// Generic trait shared by all DWARF types
pub trait DwarfType {
    #[doc(hidden)]
    fn get_base(&self) -> &ffi::DWARF_Type;

    /// Return the type's name (if any)
    fn name(&self) -> Result<String, Error> {
        to_conv_result!(
            ffi::DWARF_Type::name,
            self.get_base(),
            |e: cxx::UniquePtr<cxx::String>| { e.to_string() }
        );
    }

    /// Return the size of the type or an error if it can't be computed.
    ///
    /// This size should match the equivalent of `sizeof(Type)`.
    fn size(&self) -> Result<u64, Error> {
        to_conv_result!(
            ffi::DWARF_Type::size,
            self.get_base(),
            |e| e
        );
    }

    /// Return the debug location where this type is defined.
    fn location(&self) -> DebugLocation {
        DebugLocation::from_ffi(self.get_base().location())
    }

    /// Whether this type is a `DW_TAG_unspecified_type`.
    fn is_unspecified(&self) -> bool {
        self.get_base().is_unspecified()
    }

    /// The scope in which this function is defined
    fn scope(&self) -> Option<Scope> {
        into_optional(self.get_base().scope())
    }
}

impl DwarfType for Generic<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap()
    }
}

impl DwarfType for Type<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        match &self {
            Type::Structure(s) => {
                s.get_base()
            }
            Type::Class(s) => {
                s.get_base()
            }
            Type::Union(s) => {
                s.get_base()
            }
            Type::Pointer(s) => {
                s.get_base()
            }
            Type::Const(s) => {
                s.get_base()
            }
            Type::Base(s) => {
                s.get_base()
            }
            Type::Array(s) => {
                s.get_base()
            }
            Type::Generic(s) => {
                s.get_base()
            }
        }
    }
}

declare_fwd_iterator!(
    Types,
    Type<'a>,
    ffi::DWARF_Type,
    ffi::DWARF_CompilationUnit,
    ffi::DWARF_CompilationUnit_it_types
);

