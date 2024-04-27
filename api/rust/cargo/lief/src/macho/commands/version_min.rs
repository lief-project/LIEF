use super::Command;
use lief_ffi as ffi;
use crate::common::FromFFI;

use std::marker::PhantomData;

pub struct VersionMin<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_VersionMin>,
    _owner: PhantomData<&'a ffi::MachO_Binary>
}


impl VersionMin<'_> {
    pub fn version(&self) -> Vec<u64> {
        Vec::from(self.ptr.version().as_slice())
    }
    pub fn sdk(&self) -> Vec<u64> {
        Vec::from(self.ptr.sdk().as_slice())
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
