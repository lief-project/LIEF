use super::Command;
use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;

/// Structure that represents a `LC_DYLD_ENVIRONMENT` command which is
/// used by the Mach-O linker/loader to initialize an environment variable
pub struct DyldEnvironment<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_DyldEnvironment>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

impl DyldEnvironment<'_> {
    /// The actual environment variable
    pub fn value(&self) -> String {
        self.ptr.value().to_string()
    }
}

impl std::fmt::Debug for DyldEnvironment<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("DyldEnvironment")
            .field("base", &base)
            .field("value", &self.value())
            .finish()
    }
}

impl FromFFI<ffi::MachO_DyldEnvironment> for DyldEnvironment<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_DyldEnvironment>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Command for DyldEnvironment<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
