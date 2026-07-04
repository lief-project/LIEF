use super::Command;
use crate::common::FromFFI;
use lief_ffi as ffi;
use std::marker::PhantomData;

/// Structure that represents the Mach-O linker, also named loader.
/// Most of the time, [`Dylinker::name`] should return `/usr/lib/dyld`
pub struct Dylinker<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_Dylinker>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

impl std::fmt::Debug for Dylinker<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("Dylinker")
            .field("base", &base)
            .field("name", &self.name())
            .finish()
    }
}

impl Dylinker<'_> {
    /// Path to the linker (or loader)
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }
}

impl FromFFI<ffi::MachO_Dylinker> for Dylinker<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_Dylinker>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Command for Dylinker<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
