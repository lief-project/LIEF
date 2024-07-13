use lief_ffi as ffi;

use crate::common::FromFFI;
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
}

impl PdbType for Array<'_> {
    fn get_base(&self) -> &ffi::PDB_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
