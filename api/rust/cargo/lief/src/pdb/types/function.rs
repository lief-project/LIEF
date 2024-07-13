use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;
use crate::pdb::types::PdbType;

/// This structure wraps a `LF_PROCEDURE` PDB type
pub struct Function<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_types_Function>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::PDB_types_Function> for Function<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::PDB_types_Function>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Function<'_> {
}

impl PdbType for Function<'_> {
    fn get_base(&self) -> &ffi::PDB_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
