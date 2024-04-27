use super::Command;
use lief_ffi as ffi;
use crate::common::FromFFI;

use std::marker::PhantomData;

pub struct SubFramework<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_SubFramework>,
    _owner: PhantomData<&'a ffi::MachO_Binary>
}


impl SubFramework<'_> {
    pub fn umbrella(&self) -> String {
        self.ptr.umbrella().to_string()
    }
}

impl std::fmt::Debug for SubFramework<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("SubFramework")
            .field("base", &base)
            .field("umbrella", &self.umbrella())
            .finish()
    }
}

impl FromFFI<ffi::MachO_SubFramework> for SubFramework<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_SubFramework>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData
        }
    }
}

impl Command for SubFramework<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

