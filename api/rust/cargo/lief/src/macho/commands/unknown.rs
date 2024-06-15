use super::Command;
use lief_ffi as ffi;
use crate::common::FromFFI;

use std::marker::PhantomData;

/// Generic structure when the command is not recognized by LIEF (e.g private `LC_xxx` command)
pub struct Unknown<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_UnknownCommand>,
    _owner: PhantomData<&'a ffi::MachO_Binary>
}


impl Unknown<'_> {
    /// The original `LC_` int that is not supported by LIEF
    pub fn original_command(&self) -> u64 {
        self.ptr.original_command()
    }
}

impl std::fmt::Debug for Unknown<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("UnknownCommand")
            .field("base", &base)
            .field("original_command", &self.original_command())
            .finish()
    }
}

impl FromFFI<ffi::MachO_UnknownCommand> for Unknown<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_UnknownCommand>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData
        }
    }
}

impl Command for Unknown<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
