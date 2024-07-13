use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;

use crate::pdb::Type;
use crate::common::into_optional;
use crate::declare_fwd_iterator;

/// This class represents a Method (`LF_ONEMETHOD`) that can be defined in
/// ClassLike PDB type
pub struct Method<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_types_Method>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::PDB_types_Method> for Method<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::PDB_types_Method>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Method<'_> {
    /// Name of the method
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

}

declare_fwd_iterator!(
    Methods,
    Method<'a>,
    ffi::PDB_types_Method,
    ffi::PDB_types_ClassLike,
    ffi::PDB_types_ClassLike_it_methods
);


