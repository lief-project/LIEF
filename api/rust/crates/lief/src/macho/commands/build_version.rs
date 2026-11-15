use std::marker::PhantomData;

use lief_ffi as ffi;

use super::Command;
use crate::common::FromFFI;
use crate::{declare_iterator, enum_from_int};

enum_from_int! {
    /// Tool used during the build
    #[allow(non_camel_case_types)]
    Tool: u32 {
        CLANG = 1,
        SWIFT = 2,
        LD = 3,
        LLD = 4,
        METAL = 1024,
        AIRLLD = 1025,
        AIRNT = 1026,
        AIRNT_PLUGIN = 1027,
        AIRPACK = 1028,
        GPUARCHIVER = 1031,
        METAL_FRAMEWORK = 1032,
    }
}

/// Represents a tool version used during the build
pub struct BuildToolVersion<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_BuildToolVersion>,
    _owner: PhantomData<&'a ffi::MachO_BuildVersion>,
}

impl BuildToolVersion<'_> {
    /// The tool used
    pub fn tool(&self) -> Tool {
        Tool::from(self.ptr.tool())
    }

    /// Version associated with the tool
    pub fn version(&self) -> (u64, u64, u64) {
        let vec = Vec::from(self.ptr.version().as_slice());
        if vec.len() != 3 {
            return (0, 0, 0);
        }
        (vec[0], vec[1], vec[2])
    }
}

impl std::fmt::Debug for BuildToolVersion<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuildToolVersion")
            .field("tool", &self.tool())
            .field("version", &self.version())
            .finish()
    }
}

impl<'a> FromFFI<ffi::MachO_BuildToolVersion> for BuildToolVersion<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::MachO_BuildToolVersion>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

/// Structure that represents the `LC_BUILD_VERSION` command
pub struct BuildVersion<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_BuildVersion>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    Platform: u32 {
        MACOS = 0x00000001,
        IOS = 0x00000002,
        TVOS = 0x00000003,
        WATCHOS = 0x00000004,
        BRIDGEOS = 0x00000005,
        MAC_CATALYST = 0x00000006,
        IOS_SIMULATOR = 0x00000007,
        TVOS_SIMULATOR = 0x00000008,
        WATCHOS_SIMULATOR = 0x00000009,
        DRIVERKIT = 0x0000000A,
        VISIONOS = 0x0000000B,
        VISIONOS_SIMULATOR = 0x0000000C,
        FIRMWARE = 0x0000000D,
        SEPOS = 0x0000000E,
        MACOS_EXCLAVE_CORE = 0x0000000F,
        MACOS_EXCLAVE_KIT = 0x00000010,
        IOS_EXCLAVE_CORE = 0x00000011,
        IOS_EXCLAVE_KIT = 0x00000012,
        TVOS_EXCLAVE_CORE = 0x00000013,
        TVOS_EXCLAVE_KIT = 0x00000014,
        WATCHOS_EXCLAVE_CORE = 0x00000015,
        WATCHOS_EXCLAVE_KIT = 0x00000016,
        VISIONOS_EXCLAVE_CORE = 0x00000017,
        VISIONOS_EXCLAVE_KIT = 0x00000018,
        ANY = 0xFFFFFFFF,
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

    /// Return an iterator over the [`BuildToolVersion`] entries
    pub fn tools(&self) -> BuildTools<'_> {
        BuildTools::new(self.ptr.tools())
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

declare_iterator!(
    BuildTools,
    BuildToolVersion<'a>,
    ffi::MachO_BuildToolVersion,
    ffi::MachO_BuildVersion,
    ffi::MachO_BuildVersion_it_tools
);
