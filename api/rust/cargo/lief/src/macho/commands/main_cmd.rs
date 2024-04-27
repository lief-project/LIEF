use super::Command;
use crate::common::FromFFI;
use lief_ffi as ffi;
use std::marker::PhantomData;

pub struct Main<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_Main>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

impl Main<'_> {
    pub fn entrypoint(&self) -> u64 {
        self.ptr.entrypoint()
    }
    pub fn stack_size(&self) -> u64 {
        self.ptr.stack_size()
    }
}

impl std::fmt::Debug for Main<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("Main")
            .field("base", &base)
            .field("entrypoint", &self.entrypoint())
            .field("stack_size", &self.stack_size())
            .finish()
    }
}

impl<'a> FromFFI<ffi::MachO_Main> for Main<'a> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_Main>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Command for Main<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
