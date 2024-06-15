use super::Command;
use lief_ffi as ffi;
use crate::common::FromFFI;

use std::marker::PhantomData;

/// Structure that wraps the `LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_IPHONEOS, ...` commands.
pub struct VersionMin<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_VersionMin>,
    _owner: PhantomData<&'a ffi::MachO_Binary>
}

impl VersionMin<'_> {
    /// Version as a tuplce
    pub fn version(&self) -> (u64, u64, u64) {
        let vec = Vec::from(self.ptr.version().as_slice());
        if vec.len() != 3 {
            return (0, 0, 0);
        }
        (vec[0], vec[1], vec[2])
    }

    /// SDK version as a tuple
    pub fn sdk(&self) -> (u64, u64, u64) {
        let vec = Vec::from(self.ptr.sdk().as_slice());
        if vec.len() != 3 {
            return (0, 0, 0);
        }
        (vec[0], vec[1], vec[2])
    }
}

impl std::fmt::Debug for VersionMin<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("VersionMin")
            .field("base", &base)
            .field("version", &self.version())
            .field("sdk", &self.sdk())
            .finish()
    }
}

impl FromFFI<ffi::MachO_VersionMin> for VersionMin<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_VersionMin>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData
        }
    }
}

impl Command for VersionMin<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
