use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;
use crate::pdb::types::{PdbType, Type};

use crate::common::into_optional;

/// This structure represents a `LF_POINTER` PDB type
pub struct Pointer<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_types_Pointer>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::PDB_types_Pointer> for Pointer<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::PDB_types_Pointer>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Pointer<'_> {
    /// Underlying type targeted by this modifier
    pub fn underlying_type(&self) -> Option<Type> {
        into_optional(self.ptr.underlying_type())
    }
}

impl PdbType for Pointer<'_> {
    fn get_base(&self) -> &ffi::PDB_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
