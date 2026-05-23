#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/utils.hpp");

        type ELF_Binary = crate::elf::binary::ffi::ELF_Binary;
        type ELF_Utils;

        #[Self = "ELF_Utils"]
        fn is_elf(file: &CxxString) -> bool;
        #[Self = "ELF_Utils"]
        unsafe fn check_layout(bin: &ELF_Binary, error: *mut CxxString) -> bool;
    }
}
