use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;
use crate::pdb::types::PdbType;
use crate::pdb::types::classlike::ClassLike;

/// This structure wraps a `LF_UNION` PDB type
pub struct Union<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_types_Union>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::PDB_types_Union> for Union<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::PDB_types_Union>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Union<'_> {
}

impl PdbType for Union<'_> {
    fn get_base(&self) -> &ffi::PDB_Type {
        self.ptr.as_ref().unwrap().as_ref().as_ref()
    }
}

impl ClassLike for Union<'_> {
    fn get_classlike(&self) -> &ffi::PDB_types_ClassLike {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
