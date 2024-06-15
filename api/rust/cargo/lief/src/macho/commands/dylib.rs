use super::Command;
use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::declare_iterator;
use std::marker::PhantomData;

/// Structure which represents a library dependency
pub struct Dylib<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_Dylib>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

impl Dylib<'_> {
    /// Library name
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// Date and Time when the shared library was built
    pub fn timestamp(&self) -> u32 {
        self.ptr.timestamp()
    }

    /// Current version of the shared library
    pub fn current_version(&self) -> (u64, u64, u64) {
        let vec = Vec::from(self.ptr.current_version().as_slice());
        if vec.len() != 3 {
            return (0, 0, 0);
        }
        (vec[0], vec[1], vec[2])
    }
    /// Compatibility version of the shared library
    pub fn compatibility_version(&self) -> (u64, u64, u64) {
        let vec = Vec::from(self.ptr.compatibility_version().as_slice());
        if vec.len() != 3 {
            return (0, 0, 0);
        }
        (vec[0], vec[1], vec[2])
    }
}

impl std::fmt::Debug for Dylib<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("Dylib")
            .field("base", &base)
            .field("name", &self.name())
            .field("timestamp", &self.timestamp())
            .field("current_version", &self.current_version())
            .field("compatibility_version", &self.compatibility_version())
            .finish()
    }
}

impl FromFFI<ffi::MachO_Dylib> for Dylib<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_Dylib>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Command for Dylib<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

declare_iterator!(
    Libraries,
    Dylib<'a>,
    ffi::MachO_Dylib,
    ffi::MachO_Binary,
    ffi::MachO_Binary_it_libraries
);
