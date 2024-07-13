use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;
use crate::pdb::types::PdbType;

/// This structure wraps a `LF_BITFIELD` PDB type
pub struct BitField<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_types_BitField>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::PDB_types_BitField> for BitField<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::PDB_types_BitField>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl BitField<'_> {
}

impl PdbType for BitField<'_> {
    fn get_base(&self) -> &ffi::PDB_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
