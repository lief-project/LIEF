use std::marker::PhantomData;

use lief_ffi as ffi;

use super::Command;
use crate::common::FromFFI;

pub struct BuildVersion<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_BuildVersion>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum PLATFORM {
    MACOS,
    IOS,
    TVOS,
    WATCHOS,
    UNKNOWN(u32),
}

impl PLATFORM {
    pub fn from_value(value: u32) -> Self {
        match value {
            0x00000001 => PLATFORM::MACOS,
            0x00000002 => PLATFORM::IOS,
            0x00000003 => PLATFORM::TVOS,
            0x00000004 => PLATFORM::WATCHOS,
            _ => PLATFORM::UNKNOWN(value),
        }
    }
}

impl BuildVersion<'_> {
    pub fn sdk(&self) -> Vec<u64> {
        Vec::from(self.ptr.sdk().as_slice())
    }

    pub fn minos(&self) -> Vec<u64> {
        Vec::from(self.ptr.minos().as_slice())
    }

    pub fn platform(&self) -> PLATFORM {
        PLATFORM::from_value(self.ptr.platform())
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
