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
pub mod typedef;
pub mod atomic;
pub mod coarray;
pub mod dynamic;
pub mod enum_type;
pub mod file;
pub mod immutable;
pub mod interface;
pub mod pointer_to_member;
pub mod rvalue_ref;
pub mod reference;
pub mod restrict;
pub mod set_type;
pub mod shared;
pub mod string;
pub mod subroutine;
pub mod template_alias;
pub mod thrown;
pub mod volatile;

#[doc(inline)]
pub use classlike::Structure;

#[doc(inline)]
pub use classlike::Class;

#[doc(inline)]
pub use classlike::Union;

#[doc(inline)]
pub use classlike::Packed;

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

#[doc(inline)]
pub use typedef::Typedef;

#[doc(inline)]
pub use atomic::Atomic;

#[doc(inline)]
pub use coarray::Coarray;

#[doc(inline)]
pub use dynamic::Dynamic;

#[doc(inline)]
pub use file::File;

#[doc(inline)]
pub use immutable::Immutable;

#[doc(inline)]
pub use enum_type::Enum;

#[doc(inline)]
pub use interface::Interface;

#[doc(inline)]
pub use pointer_to_member::PointerToMember;

#[doc(inline)]
pub use rvalue_ref::RValueReference;

#[doc(inline)]
pub use reference::Reference;

#[doc(inline)]
pub use restrict::Restrict;

#[doc(inline)]
pub use set_type::SetTy;

#[doc(inline)]
pub use shared::Shared;

#[doc(inline)]
pub use string::StringTy;

#[doc(inline)]
pub use subroutine::Subroutine;

#[doc(inline)]
pub use template_alias::TemplateAlias;

#[doc(inline)]
pub use thrown::Thrown;

#[doc(inline)]
pub use volatile::Volatile;

/// This class represents a DWARF Type which includes:
///
/// - `DW_TAG_array_type`
/// - `DW_TAG_atomic_type`
/// - `DW_TAG_base_type`
/// - `DW_TAG_class_type`
/// - `DW_TAG_coarray_type`
/// - `DW_TAG_const_type`
/// - `DW_TAG_dynamic_type`
/// - `DW_TAG_enumeration_type`
/// - `DW_TAG_file_type`
/// - `DW_TAG_immutable_type`
/// - `DW_TAG_interface_type`
/// - `DW_TAG_packed_type`
/// - `DW_TAG_pointer_type`
/// - `DW_TAG_ptr_to_member_type`
/// - `DW_TAG_reference_type`
/// - `DW_TAG_restrict_type`
/// - `DW_TAG_rvalue_reference_type`
/// - `DW_TAG_set_type`
/// - `DW_TAG_shared_type`
/// - `DW_TAG_string_type`
/// - `DW_TAG_structure_type`
/// - `DW_TAG_subroutine_type`
/// - `DW_TAG_template_alias`
/// - `DW_TAG_thrown_type`
/// - `DW_TAG_typedef`
/// - `DW_TAG_union_type`
/// - `DW_TAG_unspecified_type`
/// - `DW_TAG_volatile_type`d_type`
pub enum Type<'a> {
    /// Interface over `DW_TAG_structure_type`
    Structure(Structure<'a>),

    /// Interface over `DW_TAG_class_type`
    Class(Class<'a>),

    /// Interface over `DW_TAG_union_type`
    Union(Union<'a>),

    /// Interface over `DW_TAG_packed_type`
    Packed(Packed<'a>),

    /// Interface over `DW_TAG_pointer_type`
    Pointer(Pointer<'a>),

    /// Interface over `DW_TAG_const_type`
    Const(Const<'a>),

    /// Interface over `DW_TAG_base_type`
    Base(Base<'a>),

    /// Interface over `DW_TAG_array_type`
    Array(Array<'a>),

    /// Interface over `DW_TAG_typedef`
    Typedef(Typedef<'a>),

    /// Interface over `DW_TAG_atomic_type`
    Atomic(Atomic<'a>),

    /// Interface over `DW_TAG_coarray_type`
    Coarray(Coarray<'a>),

    /// Interface over `DW_TAG_dynamic_type`
    Dynamic(Dynamic<'a>),

    /// Interface over `DW_TAG_enumeration_type`
    Enum(Enum<'a>),

    /// Interface over `DW_TAG_file_type`
    File(File<'a>),

    /// Interface over `DW_TAG_immutable_type`
    Immutable(Immutable<'a>),

    /// Interface over `DW_TAG_interface_type`
    Interface(Interface<'a>),

    /// Interface over `DW_TAG_ptr_to_member_type`
    PointerToMember(PointerToMember<'a>),

    /// Interface over `DW_TAG_rvalue_reference_type`
    RValueReference(RValueReference<'a>),

    /// Interface over `DW_TAG_reference_type`
    Reference(Reference<'a>),

    /// Interface over `DW_TADW_TAG_restrict_type`
    Restrict(Restrict<'a>),

    /// Interface over `DW_TAG_set_type`
    SetTy(SetTy<'a>),

    /// Interface over `DW_TAG_shared_type`
    Shared(Shared<'a>),

    /// Interface over `DW_TAG_string_type`
    StringTy(StringTy<'a>),

    /// Interface over `DW_TAG_subroutine_type`
    Subroutine(Subroutine<'a>),

    /// Interface over `DW_TAG_template_alias`
    TemplateAlias(TemplateAlias<'a>),

    /// Interface over `DW_TAG_thrown_type`
    Thrown(Thrown<'a>),

    /// Interface over `DW_TAG_volatile_type`
    Volatile(Volatile<'a>),

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
            } else if ffi::DWARF_types_Packed::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_Packed>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Packed(Packed::from_ffi(raw))
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
            } else if ffi::DWARF_types_Typedef::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_Typedef>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Typedef(Typedef::from_ffi(raw))
            } else if ffi::DWARF_types_Atomic::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_Atomic>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Atomic(Atomic::from_ffi(raw))
            } else if ffi::DWARF_types_Coarray::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_Coarray>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Coarray(Coarray::from_ffi(raw))
            } else if ffi::DWARF_types_Dynamic::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_Dynamic>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Dynamic(Dynamic::from_ffi(raw))
            } else if ffi::DWARF_types_Enum::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_Enum>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Enum(Enum::from_ffi(raw))
            } else if ffi::DWARF_types_File::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_File>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::File(File::from_ffi(raw))
            } else if ffi::DWARF_types_Immutable::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_Immutable>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Immutable(Immutable::from_ffi(raw))
            } else if ffi::DWARF_types_Interface::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_Interface>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Interface(Interface::from_ffi(raw))
            } else if ffi::DWARF_types_PointerToMember::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_PointerToMember>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::PointerToMember(PointerToMember::from_ffi(raw))
            } else if ffi::DWARF_types_RValueReference::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_RValueReference>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::RValueReference(RValueReference::from_ffi(raw))
            } else if ffi::DWARF_types_Reference::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_Reference>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Reference(Reference::from_ffi(raw))
            } else if ffi::DWARF_types_Restrict::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_Restrict>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Restrict(Restrict::from_ffi(raw))
            } else if ffi::DWARF_types_SetTy::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_SetTy>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::SetTy(SetTy::from_ffi(raw))
            } else if ffi::DWARF_types_Shared::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_Shared>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Shared(Shared::from_ffi(raw))
            } else if ffi::DWARF_types_StringTy::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_StringTy>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::StringTy(StringTy::from_ffi(raw))
            } else if ffi::DWARF_types_Subroutine::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_Subroutine>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Subroutine(Subroutine::from_ffi(raw))
            } else if ffi::DWARF_types_TemplateAlias::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_TemplateAlias>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::TemplateAlias(TemplateAlias::from_ffi(raw))
            } else if ffi::DWARF_types_Thrown::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_Thrown>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Thrown(Thrown::from_ffi(raw))
            } else if ffi::DWARF_types_Volatile::classof(type_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Type>;
                    type To = cxx::UniquePtr<ffi::DWARF_types_Volatile>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Type::Volatile(Volatile::from_ffi(raw))
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

    /// Return the type's name using either `DW_AT_name` or `DW_AT_picture_string` (if any)
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
            Type::Packed(s) => {
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
            Type::Typedef(s) => {
                s.get_base()
            }
            Type::Atomic(s) => {
                s.get_base()
            }
            Type::Coarray(s) => {
                s.get_base()
            }
            Type::Dynamic(s) => {
                s.get_base()
            }
            Type::Enum(s) => {
                s.get_base()
            }
            Type::File(s) => {
                s.get_base()
            }
            Type::Immutable(s) => {
                s.get_base()
            }
            Type::Interface(s) => {
                s.get_base()
            }
            Type::PointerToMember(s) => {
                s.get_base()
            }
            Type::RValueReference(s) => {
                s.get_base()
            }
            Type::Reference(s) => {
                s.get_base()
            }
            Type::Restrict(s) => {
                s.get_base()
            }
            Type::SetTy(s) => {
                s.get_base()
            }
            Type::Shared(s) => {
                s.get_base()
            }
            Type::StringTy(s) => {
                s.get_base()
            }
            Type::Subroutine(s) => {
                s.get_base()
            }
            Type::TemplateAlias(s) => {
                s.get_base()
            }
            Type::Thrown(s) => {
                s.get_base()
            }
            Type::Volatile(s) => {
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

