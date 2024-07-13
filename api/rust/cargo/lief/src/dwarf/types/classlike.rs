use lief_ffi as ffi;

use crate::common::{into_optional, FromFFI};
use crate::declare_fwd_iterator;
use crate::dwarf::types::DwarfType;
use crate::to_result;
use std::marker::PhantomData;
use crate::Error;
use super::Type;

/// Trait shared by [`Structure`], [`Class`] or [`Union`]
pub trait ClassLike {
    #[doc(hidden)]
    fn get_classlike(&self) -> &ffi::DWARF_types_ClassLike;

    /// Return this list of all the attributes defined in this class-like type
    fn members(&self) -> Members {
        Members::new(self.get_classlike().members())
    }
}

pub struct Member<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_ClassLike_Member>,
    _owner: PhantomData<&'a ()>,
}

impl Member<'_> {
    /// Name of the member
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// Offset of the current member in the struct/union/class
    pub fn offset(&self) -> Result<u64, Error> {
        to_result!(ffi::DWARF_types_ClassLike_Member::offset, self);
    }

    /// Offset of the current member in **bits** the struct/union/class
    ///
    /// This function differs from [`Member::offset`] for aggregates using bit-field
    /// declaration:
    ///
    /// ```cpp
    /// struct S {
    ///   int flag : 4;
    ///   int opt : 1
    /// };
    /// ```
    ///
    /// Usually, `offset() * 8 == bit_offset()`
    pub fn bit_offset(&self) -> Result<u64, Error> {
        to_result!(ffi::DWARF_types_ClassLike_Member::offset, self);
    }

    /// Type of the current member
    pub fn get_type(&self) -> Option<Type> {
        into_optional(self.ptr.get_type())
    }

    pub fn is_external(&self) -> bool {
        self.ptr.is_external()
    }

    pub fn is_declaration(&self) -> bool {
        self.ptr.is_declaration()
    }
}

impl FromFFI<ffi::DWARF_types_ClassLike_Member> for Member<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_types_ClassLike_Member>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

/// This structure represents a `DW_TAG_structure_type` DWARF type
pub struct Structure<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_Structure>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_Structure> for Structure<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_types_Structure>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl DwarfType for Structure<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref().as_ref()
    }
}

impl ClassLike for Structure<'_> {
    fn get_classlike(&self) -> &ffi::DWARF_types_ClassLike {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

/// This structure represents a `DW_TAG_union_type` DWARF type
pub struct Union<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_Union>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_Union> for Union<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_types_Union>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl DwarfType for Union<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref().as_ref()
    }
}

impl ClassLike for Union<'_> {
    fn get_classlike(&self) -> &ffi::DWARF_types_ClassLike {
        self.ptr.as_ref().unwrap().as_ref()
    }
}


/// This structure represents a `DW_TAG_class_type` DWARF type
pub struct Class<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_Class>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_Class> for Class<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_types_Class>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl DwarfType for Class<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref().as_ref()
    }
}

impl ClassLike for Class<'_> {
    fn get_classlike(&self) -> &ffi::DWARF_types_ClassLike {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

declare_fwd_iterator!(
    Members,
    Member<'a>,
    ffi::DWARF_types_ClassLike_Member,
    ffi::DWARF_types_ClassLike,
    ffi::DWARF_types_ClassLike_it_members
);
