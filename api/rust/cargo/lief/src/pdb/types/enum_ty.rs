use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;
use crate::pdb::types::PdbType;

/// This structure wraps a `LF_ENUM` PDB type
pub struct Enum<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_types_Enum>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::PDB_types_Enum> for Enum<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::PDB_types_Enum>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Enum<'_> {
}

impl PdbType for Enum<'_> {
    fn get_base(&self) -> &ffi::PDB_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
