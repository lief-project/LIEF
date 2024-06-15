use std::marker::PhantomData;

use lief_ffi as ffi;

use super::Command;
use crate::common::FromFFI;

/// Structure that represents the `LC_BUILD_VERSION` command
pub struct BuildVersion<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_BuildVersion>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Platform {
    MACOS,
    IOS,
    TVOS,
    WATCHOS,
    UNKNOWN(u32),
}

impl From<u32> for Platform {
    fn from(value: u32) -> Self {
        match value {
            0x00000001 => Platform::MACOS,
            0x00000002 => Platform::IOS,
            0x00000003 => Platform::TVOS,
            0x00000004 => Platform::WATCHOS,
            _ => Platform::UNKNOWN(value),
        }
    }
}

impl BuildVersion<'_> {
    pub fn sdk(&self) -> (u64, u64, u64) {
        let vec = Vec::from(self.ptr.sdk().as_slice());
        if vec.len() != 3 {
            return (0, 0, 0);
        }
        (vec[0], vec[1], vec[2])
    }

    pub fn minos(&self) -> (u64, u64, u64) {
        let vec = Vec::from(self.ptr.sdk().as_slice());
        if vec.len() != 3 {
            return (0, 0, 0);
        }
        (vec[0], vec[1], vec[2])
    }

    pub fn platform(&self) -> Platform {
        Platform::from(self.ptr.platform())
    }
}

impl std::fmt::Debug for BuildVersion<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("BuildVersion")
            .field("base", &base)
            .field("sdk", &self.sdk())
            .field("minos", &self.minos())
            .field("platform", &self.platform())
            .finish()
    }
}

impl FromFFI<ffi::MachO_BuildVersion> for BuildVersion<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_BuildVersion>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Command for BuildVersion<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
