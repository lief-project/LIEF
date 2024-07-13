use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;
use crate::pdb::types::PdbType;

/// This class represents a primitive types (int, float, ...) which are
/// also named *simple* types in the PDB format.
pub struct Simple<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_types_Simple>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::PDB_types_Simple> for Simple<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::PDB_types_Simple>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Simple<'_> {
}

impl PdbType for Simple<'_> {
    fn get_base(&self) -> &ffi::PDB_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
