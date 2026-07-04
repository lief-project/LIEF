use super::Command;
use crate::common::FromFFI;
use crate::to_slice;
use lief_ffi as ffi;
use std::marker::PhantomData;

/// Structure which represents the `LC_ATOM_INFO` command
pub struct AtomInfo<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_AtomInfo>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

impl AtomInfo<'_> {
    /// Offset in the `__LINKEDIT` segment where the payload is located
    pub fn data_offset(&self) -> u32 {
        self.ptr.data_offset()
    }

    /// Size of the payload
    pub fn data_size(&self) -> u32 {
        self.ptr.data_size()
    }

    /// Raw payload as a slice of bytes
    pub fn content(&self) -> &[u8] {
        to_slice!(self.ptr.content());
    }
}

impl std::fmt::Debug for AtomInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("AtomInfo")
            .field("base", &base)
            .field("data_offset", &self.data_offset())
            .field("data_size", &self.data_size())
            .finish()
    }
}

impl FromFFI<ffi::MachO_AtomInfo> for AtomInfo<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_AtomInfo>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Command for AtomInfo<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
