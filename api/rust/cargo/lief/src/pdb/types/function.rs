use lief_ffi as ffi;

use crate::common::{FromFFI, into_optional};
use std::marker::PhantomData;
use crate::pdb::types::PdbType;
use super::Type;
use crate::declare_fwd_iterator;

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
    /// [`Type`] returned by the function
    pub fn return_type(&self) -> Option<Type<'_>> {
        into_optional(self.ptr.return_type())
    }

    /// [`Type`] of the function's parameters
    pub fn parameters(&self) -> ParametersIt<'_> {
        ParametersIt::new(self.ptr.parameters())
    }
}

impl PdbType for Function<'_> {
    fn get_base(&self) -> &ffi::PDB_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

declare_fwd_iterator!(
    ParametersIt,
    Type<'a>,
    ffi::PDB_Type,
    ffi::PDB_types_Function,
    ffi::PDB_types_Function_it_parameters
);
