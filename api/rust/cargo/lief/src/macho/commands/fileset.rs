use super::Command;
use crate::common::FromFFI;
use lief_ffi as ffi;
use std::marker::PhantomData;


pub struct Fileset<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_Fileset>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

impl Fileset<'_> {
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    pub fn virtual_address(&self) -> u64 {
        self.ptr.virtual_address()
    }

    pub fn file_offset(&self) -> u64 {
        self.ptr.file_offset()
    }
}

impl std::fmt::Debug for Fileset<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("Note")
            .field("base", &base)
            .field("name", &self.name())
            .field("virtual_address", &self.virtual_address())
            .field("file_offset", &self.file_offset())
            .finish()
    }
}

impl<'a> FromFFI<ffi::MachO_Fileset> for Fileset<'a> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_Fileset>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Command for Fileset<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
