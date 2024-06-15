use super::Command;
use lief_ffi as ffi;
use crate::common::FromFFI;
use crate::to_slice;

use std::marker::PhantomData;

/// Structure which represents the `LC_TWOLEVEL_HINTS` command
pub struct TwoLevelHints<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_TwoLevelHints>,
    _owner: PhantomData<&'a ffi::MachO_Binary>
}

impl TwoLevelHints<'_> {
    /// Offset of the command. It should point in the `__LINKEDIT` segment
    pub fn offset(&self) -> u32 {
        self.ptr.offset()
    }
    pub fn original_nb_hints(&self) -> u32 {
        self.ptr.original_nb_hints()
    }

    /// Original payload of the command
    pub fn content(&self) -> &[u8] {
        to_slice!(self.ptr.content());
    }
}

impl std::fmt::Debug for TwoLevelHints<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("TwoLevelHints")
            .field("base", &base)
            .field("offset", &self.offset())
            .finish()
    }
}

impl FromFFI<ffi::MachO_TwoLevelHints> for TwoLevelHints<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_TwoLevelHints>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData
        }
    }
}

impl Command for TwoLevelHints<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

