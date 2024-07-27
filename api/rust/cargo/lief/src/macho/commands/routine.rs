use super::Command;
use lief_ffi as ffi;
use crate::common::FromFFI;
use std::marker::PhantomData;

/// Class that represents the `LC_ROUTINE/LC_ROUTINE64` commands.
/// Accodring to the Mach-O `loader.h` documentation:
///
/// > The routines command contains the address of the dynamic shared library
/// > initialization routine and an index into the module table for the module
/// > that defines the routine.  Before any modules are used from the library the
/// > dynamic linker fully binds the module that defines the initialization routine
/// > and then calls it.  This gets called before any module initialization
/// > routines (used for C++ static constructors) in the library.
pub struct Routine<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_Routine>,
    _owner: PhantomData<&'a ffi::MachO_Binary>
}

impl Routine<'_> {
    /// address of initialization routine
    pub fn init_address(&self) -> u64 {
        self.ptr.init_address()
    }

    /// Index into the module table that the init routine is defined in
    pub fn init_module(&self) -> u64 {
        self.ptr.init_module()
    }

    pub fn reserved1(&self) -> u64 {
        self.ptr.reserved1()
    }

    pub fn reserved2(&self) -> u64 {
        self.ptr.reserved2()
    }

    pub fn reserved3(&self) -> u64 {
        self.ptr.reserved3()
    }

    pub fn reserved4(&self) -> u64 {
        self.ptr.reserved4()
    }

    pub fn reserved5(&self) -> u64 {
        self.ptr.reserved5()
    }

    pub fn reserved6(&self) -> u64 {
        self.ptr.reserved6()
    }
}

impl std::fmt::Debug for Routine<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("Routine")
            .field("base", &base)
            .field("init_address", &self.init_address())
            .field("init_module", &self.init_module())
            .field("reserved1", &self.reserved1())
            .field("reserved2", &self.reserved2())
            .field("reserved3", &self.reserved3())
            .field("reserved4", &self.reserved4())
            .field("reserved5", &self.reserved5())
            .field("reserved6", &self.reserved6())
            .finish()
    }
}

impl FromFFI<ffi::MachO_Routine> for Routine<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_Routine>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData
        }
    }
}

impl Command for Routine<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

