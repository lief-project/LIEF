use lief_ffi as ffi;
use super::Command;
use crate::common::FromFFI;
use crate::to_slice;

use std::marker::PhantomData;

pub struct ThreadCommand<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_ThreadCommand>,
    _owner: PhantomData<&'a ffi::MachO_Binary>
}


impl ThreadCommand<'_> {
    pub fn flavor(&self) -> u32 {
        self.ptr.flavor()
    }
    pub fn count(&self) -> u32 {
        self.ptr.count()
    }
    pub fn pc(&self) -> u64 {
        self.ptr.pc()
    }
    pub fn state(&self) -> &[u8] {
        to_slice!(self.ptr.state());
    }
}

impl std::fmt::Debug for ThreadCommand<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("ThreadCommand")
            .field("base", &base)
            .field("flavor", &self.flavor())
            .field("count", &self.count())
            .field("pc", &self.pc())
            .finish()
    }
}

impl FromFFI<ffi::MachO_ThreadCommand> for ThreadCommand<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_ThreadCommand>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData
        }
    }
}

impl Command for ThreadCommand<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
