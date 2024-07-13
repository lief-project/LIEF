use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;
use crate::pdb::types::{PdbType, Type};

use crate::common::into_optional;

/// This structure wraps a `LF_MODIFIER` PDB type
pub struct Modifier<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_types_Modifier>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::PDB_types_Modifier> for Modifier<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::PDB_types_Modifier>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Modifier<'_> {
    /// Underlying type targeted by this modifier
    pub fn underlying_type(&self) -> Option<Type> {
        into_optional(self.ptr.underlying_type())
    }
}

impl PdbType for Modifier<'_> {
    fn get_base(&self) -> &ffi::PDB_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
