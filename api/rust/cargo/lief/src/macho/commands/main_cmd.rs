use super::Command;
use crate::common::FromFFI;
use lief_ffi as ffi;
use std::marker::PhantomData;

/// Structure that represent the `LC_MAIN` command. This kind of command can be used to determine the
/// entrypoint of an executable.
pub struct Main<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_Main>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

impl Main<'_> {
    /// Offset of the *main* function **relative** to the `__TEXT`
    /// segment
    pub fn entrypoint(&self) -> u64 {
        self.ptr.entrypoint()
    }

    /// The initial stack size
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
