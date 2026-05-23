use std::marker::PhantomData;

use lief_ffi as ffi;

use super::Command;
use crate::common::FromFFI;
use crate::declare_iterator;

/// Tool used during the build
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Tool {
    CLANG,
    SWIFT,
    LD,
    LLD,
    METAL,
    AIRLLD,
    AIRNT,
    AIRNT_PLUGIN,
    AIRPACK,
    GPUARCHIVER,
    METAL_FRAMEWORK,
    UNKNOWN(u32),
}

impl From<u32> for Tool {
    fn from(value: u32) -> Self {
        match value {
            1 => Tool::CLANG,
            2 => Tool::SWIFT,
            3 => Tool::LD,
            4 => Tool::LLD,
            1024 => Tool::METAL,
            1025 => Tool::AIRLLD,
            1026 => Tool::AIRNT,
            1027 => Tool::AIRNT_PLUGIN,
            1028 => Tool::AIRPACK,
            1031 => Tool::GPUARCHIVER,
            1032 => Tool::METAL_FRAMEWORK,
            _ => Tool::UNKNOWN(value),
        }
    }
}

impl From<Tool> for u32 {
    fn from(value: Tool) -> u32 {
        match value {
            Tool::CLANG => 1,
            Tool::SWIFT => 2,
            Tool::LD => 3,
            Tool::LLD => 4,
            Tool::METAL => 1024,
            Tool::AIRLLD => 1025,
            Tool::AIRNT => 1026,
            Tool::AIRNT_PLUGIN => 1027,
            Tool::AIRPACK => 1028,
            Tool::GPUARCHIVER => 1031,
            Tool::METAL_FRAMEWORK => 1032,
            Tool::UNKNOWN(v) => v,
        }
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

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Platform {
    MACOS,
    IOS,
    TVOS,
    WATCHOS,
    BRIDGEOS,
    MAC_CATALYST,
    IOS_SIMULATOR,
    TVOS_SIMULATOR,
    WATCHOS_SIMULATOR,
    DRIVERKIT,
    VISIONOS,
    VISIONOS_SIMULATOR,
    FIRMWARE,
    SEPOS,
    MACOS_EXCLAVE_CORE,
    MACOS_EXCLAVE_KIT,
    IOS_EXCLAVE_CORE,
    IOS_EXCLAVE_KIT,
    TVOS_EXCLAVE_CORE,
    TVOS_EXCLAVE_KIT,
    WATCHOS_EXCLAVE_CORE,
    WATCHOS_EXCLAVE_KIT,
    VISIONOS_EXCLAVE_CORE,
    VISIONOS_EXCLAVE_KIT,
    ANY,
    UNKNOWN(u32),
}

impl From<u32> for Platform {
    fn from(value: u32) -> Self {
        match value {
            0x00000001 => Platform::MACOS,
            0x00000002 => Platform::IOS,
            0x00000003 => Platform::TVOS,
            0x00000004 => Platform::WATCHOS,
            0x00000005 => Platform::BRIDGEOS,
            0x00000006 => Platform::MAC_CATALYST,
            0x00000007 => Platform::IOS_SIMULATOR,
            0x00000008 => Platform::TVOS_SIMULATOR,
            0x00000009 => Platform::WATCHOS_SIMULATOR,
            0x0000000A => Platform::DRIVERKIT,
            0x0000000B => Platform::VISIONOS,
            0x0000000C => Platform::VISIONOS_SIMULATOR,
            0x0000000D => Platform::FIRMWARE,
            0x0000000E => Platform::SEPOS,
            0x0000000F => Platform::MACOS_EXCLAVE_CORE,
            0x00000010 => Platform::MACOS_EXCLAVE_KIT,
            0x00000011 => Platform::IOS_EXCLAVE_CORE,
            0x00000012 => Platform::IOS_EXCLAVE_KIT,
            0x00000013 => Platform::TVOS_EXCLAVE_CORE,
            0x00000014 => Platform::TVOS_EXCLAVE_KIT,
            0x00000015 => Platform::WATCHOS_EXCLAVE_CORE,
            0x00000016 => Platform::WATCHOS_EXCLAVE_KIT,
            0x00000017 => Platform::VISIONOS_EXCLAVE_CORE,
            0x00000018 => Platform::VISIONOS_EXCLAVE_KIT,
            0xFFFFFFFF => Platform::ANY,
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
