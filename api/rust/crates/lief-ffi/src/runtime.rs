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

#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime.hpp");
        include!("LIEF/rust/COFF/Section.hpp");

        fn runtime_enabled() -> bool;
        fn runtime_platform() -> u32;
        fn runtime_arch() -> u32;
    }
}
