use lief_ffi as ffi;
use super::Command;
use crate::common::FromFFI;
use crate::to_slice;

use crate::macho::header::CpuType;
use std::marker::PhantomData;

/// Structure that represents the `LC_THREAD` / `LC_UNIXTHREAD` commands and that
/// can be used to get the binary entrypoint when the `LC_MAIN` is not present
///
/// Generally speaking, this command aims at defining the original state
/// of the main thread which includes the registers' values
pub struct ThreadCommand<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_ThreadCommand>,
    _owner: PhantomData<&'a ffi::MachO_Binary>
}

impl ThreadCommand<'_> {

    /// Integer that defines a special *flavor* for the thread.
    ///
    /// The meaning of this value depends on the architecture. The list of
    /// the values can be found in the XNU kernel files:
    /// - xnu/osfmk/mach/arm/thread_status.h  for the ARM/AArch64 architectures
    /// - xnu/osfmk/mach/i386/thread_status.h for the x86/x86-64 architectures
    pub fn flavor(&self) -> u32 {
        self.ptr.flavor()
    }

    /// The CPU architecture that is targeted by this Thread Command
    pub fn architecture(&self) -> CpuType {
        CpuType::from(self.ptr.architecture())
    }

    /// Size of the thread state data with 32-bits alignment.
    ///
    /// This value should match `state().len()`
    pub fn count(&self) -> u32 {
        self.ptr.count()
    }

    /// Return the initial Program Counter regardless of the underlying architecture.
    /// This value, when non null, can be used to determine the binary's entrypoint.
    ///
    /// Underneath, it works by looking for the PC register value in the [`ThreadCommand::state`]
    /// data
    pub fn pc(&self) -> u64 {
        self.ptr.pc()
    }

    /// The actual thread state as a vector of bytes. Depending on the architecture(),
    /// these data can be casted into `x86_thread_state_t, x86_thread_state64_t, ...`
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
