use super::Command;
use lief_ffi as ffi;
use crate::common::FromFFI;

use std::marker::PhantomData;

/// Class that represents the SubFramework command.
/// Accodring to the Mach-O ``loader.h`` documentation:
///
/// > A dynamically linked shared library may be a subframework of an umbrella
/// > framework.  If so it will be linked with "-umbrella umbrella_name" where
/// > Where "umbrella_name" is the name of the umbrella framework. A subframework
/// > can only be linked against by its umbrella framework or other subframeworks
/// > that are part of the same umbrella framework.  Otherwise the static link
/// > editor produces an error and states to link against the umbrella framework.
/// > The name of the umbrella framework for subframeworks is recorded in the
/// > following structure.
pub struct SubFramework<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_SubFramework>,
    _owner: PhantomData<&'a ffi::MachO_Binary>
}


impl SubFramework<'_> {
    /// Name of the umbrella framework
    pub fn umbrella(&self) -> String {
        self.ptr.umbrella().to_string()
    }
}

impl std::fmt::Debug for SubFramework<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("SubFramework")
            .field("base", &base)
            .field("umbrella", &self.umbrella())
            .finish()
    }
}

impl FromFFI<ffi::MachO_SubFramework> for SubFramework<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_SubFramework>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData
        }
    }
}

impl Command for SubFramework<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

