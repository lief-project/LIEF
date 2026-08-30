//! This module contains all LIEF's runtime API

pub mod android;
pub mod assembler;
pub mod disassembler;
pub mod host;
pub mod linux;
pub mod memory;
pub mod memory_layout;
pub mod module;
pub mod osx;
pub mod process;
pub mod windows;

#[doc(inline)]
pub use assembler::{assemble, assemble_with_config};

#[doc(inline)]
pub use disassembler::disassemble;

#[doc(inline)]
pub use host::Host;

#[doc(inline)]
pub use process::Process;

#[doc(inline)]
pub use module::{Module, Modules, module_from_addr, module_from_name, module_from_path, modules};

#[doc(inline)]
pub use memory::Memory;

#[doc(inline)]
pub use memory_layout::{Region, RegionsIt, memory_layout};

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Arch {
    NONE,
    X86_64,
    ARM64,
    RISCV64,
    UNKNOWN(u32),
}

impl From<u32> for Arch {
    fn from(value: u32) -> Self {
        match value {
            0x00000000 => Arch::NONE,
            0x00000001 => Arch::X86_64,
            0x00000002 => Arch::ARM64,
            0x00000003 => Arch::RISCV64,
            _ => Arch::UNKNOWN(value),
        }
    }
}
impl From<Arch> for u32 {
    fn from(value: Arch) -> u32 {
        match value {
            Arch::NONE => 0x00000000,
            Arch::X86_64 => 0x00000001,
            Arch::ARM64 => 0x00000002,
            Arch::RISCV64 => 0x00000003,
            Arch::UNKNOWN(value) => value,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Platform {
    NONE,
    LINUX,
    WINDOWS,
    ANDROID,
    OSX,
    IOS,
    UNKNOWN(u32),
}

impl From<u32> for Platform {
    fn from(value: u32) -> Self {
        match value {
            0x00000000 => Platform::NONE,
            0x00000001 => Platform::LINUX,
            0x00000002 => Platform::WINDOWS,
            0x00000003 => Platform::ANDROID,
            0x00000004 => Platform::OSX,
            0x00000005 => Platform::IOS,
            _ => Platform::UNKNOWN(value),
        }
    }
}

impl From<Platform> for u32 {
    fn from(value: Platform) -> u32 {
        match value {
            Platform::NONE => 0x00000000,
            Platform::LINUX => 0x00000001,
            Platform::WINDOWS => 0x00000002,
            Platform::ANDROID => 0x00000003,
            Platform::OSX => 0x00000004,
            Platform::IOS => 0x00000005,
            Platform::UNKNOWN(value) => value,
        }
    }
}

/// Whether runtime features are enabled
pub fn enabled() -> bool {
    lief_ffi::runtime_enabled()
}

/// Platform for which the runtime is compiled
pub fn platform() -> Platform {
    Platform::from(lief_ffi::runtime_platform())
}

/// Architecture for which the runtime is compiled
pub fn arch() -> Arch {
    Arch::from(lief_ffi::runtime_arch())
}
