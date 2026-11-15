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
pub use module::{
    Module, Modules, current_module, module_from_addr, module_from_name, module_from_path, modules,
};

#[doc(inline)]
pub use memory::Memory;

#[doc(inline)]
pub use memory_layout::{Region, RegionsIt, memory_layout};

use crate::enum_from_int;

enum_from_int! {
    #[allow(non_camel_case_types)]
    Arch: u32 {
        NONE = 0x00000000,
        X86_64 = 0x00000001,
        ARM64 = 0x00000002,
        RISCV64 = 0x00000003,
    }
}
enum_from_int! {
    #[allow(non_camel_case_types)]
    Platform: u32 {
        NONE = 0x00000000,
        LINUX = 0x00000001,
        WINDOWS = 0x00000002,
        ANDROID = 0x00000003,
        OSX = 0x00000004,
        IOS = 0x00000005,
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
