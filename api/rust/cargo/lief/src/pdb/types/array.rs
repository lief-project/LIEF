use lief_ffi as ffi;

use crate::{common::{FromFFI, into_optional}, pdb::Type};
use std::marker::PhantomData;
use crate::pdb::types::PdbType;

/// This structure wraps a `LF_ARRAY` PDB type
pub struct Array<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_types_Array>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::PDB_types_Array> for Array<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::PDB_types_Array>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Array<'_> {
    /// The number of element in this array
    pub fn numberof_elements(&self) -> u64 {
        self.ptr.numberof_elements()
    }

    /// Type of the elements
    pub fn element_type(&self) -> Option<Type<'_>> {
        into_optional(self.ptr.element_type())
    }

    /// Type of the index
    pub fn index_type(&self) -> Option<Type<'_>> {
        into_optional(self.ptr.index_type())
    }
}

impl PdbType for Array<'_> {
    fn get_base(&self) -> &ffi::PDB_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
