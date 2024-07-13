use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;

use crate::pdb::Type;
use crate::common::into_optional;
use crate::declare_fwd_iterator;

/// This class represents an attribute (`LF_MEMBER`) in an aggregate (class,
/// struct, union, ...)
pub struct Attribute<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_types_Attribute>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::PDB_types_Attribute> for Attribute<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::PDB_types_Attribute>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Attribute<'_> {
    /// Name of the attribute
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// Offset of this attribute in the aggregate
    pub fn field_offset(&self) -> u64 {
        self.ptr.field_offset()
    }

    /// Type of this attribute
    pub fn get_type(&self) -> Option<Type> {
        into_optional(self.ptr.get_type())
    }
}

declare_fwd_iterator!(
    Attributes,
    Attribute<'a>,
    ffi::PDB_types_Attribute,
    ffi::PDB_types_ClassLike,
    ffi::PDB_types_ClassLike_it_attributes
);


