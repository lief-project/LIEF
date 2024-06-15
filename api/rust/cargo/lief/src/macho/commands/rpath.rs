use super::Command;
use lief_ffi as ffi;
use crate::common::FromFFI;
use std::marker::PhantomData;

/// Structure that represents the `LC_RPATH` command.
///
/// This command is used to add path for searching libraries
/// associated with the `@rpath` prefix.
pub struct RPath<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_RPathCommand>,
    _owner: PhantomData<&'a ffi::MachO_Binary>
}

impl RPath<'_> {
    /// The rpath value as a string
    pub fn path(&self) -> String {
        self.ptr.path().to_string()
    }
}

impl std::fmt::Debug for RPath<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("RPath")
            .field("base", &base)
            .field("path", &self.path())
            .finish()
    }
}

impl FromFFI<ffi::MachO_RPathCommand> for RPath<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_RPathCommand>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData
        }
    }
}

impl Command for RPath<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

