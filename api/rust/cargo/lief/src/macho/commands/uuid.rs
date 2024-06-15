use super::Command;
use lief_ffi as ffi;
use crate::common::FromFFI;

use std::marker::PhantomData;

/// Structure that represents the `LC_UUID` command
pub struct UUID<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_UUIDCommand>,
    _owner: PhantomData<&'a ffi::MachO_Binary>
}


impl UUID<'_> {
    /// The UUID as a 16-bytes array
    pub fn uuid(&self) -> Vec<u64> {
        Vec::from(self.ptr.uuid().as_slice())
    }
}

impl std::fmt::Debug for UUID<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("UUID")
            .field("base", &base)
            .field("uuid", &self.uuid())
            .finish()
    }
}

impl FromFFI<ffi::MachO_UUIDCommand> for UUID<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_UUIDCommand>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData
        }
    }
}

impl Command for UUID<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
