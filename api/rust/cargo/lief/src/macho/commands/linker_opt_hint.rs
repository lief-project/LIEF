use super::Command;
use crate::common::FromFFI;
use crate::to_slice;
use lief_ffi as ffi;

use std::marker::PhantomData;

/// Structure which represents the `LC_LINKER_OPTIMIZATION_HINT` command
pub struct LinkerOptHint<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_LinkerOptHint>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

impl LinkerOptHint<'_> {
    /// Offset in the binary where the *hint* starts
    pub fn data_offset(&self) -> u32 {
        self.ptr.data_offset()
    }

    /// Size of the payload
    pub fn data_size(&self) -> u32 {
        self.ptr.data_size()
    }

    /// Payload as a slice of bytes
    pub fn content(&self) -> &[u8] {
        to_slice!(self.ptr.content());
    }
}

impl std::fmt::Debug for LinkerOptHint<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("LinkerOptHint")
            .field("base", &base)
            .field("data_offset", &self.data_offset())
            .field("data_size", &self.data_size())
            .finish()
    }
}

impl FromFFI<ffi::MachO_LinkerOptHint> for LinkerOptHint<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_LinkerOptHint>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Command for LinkerOptHint<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
