#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/utils.hpp");

        type MachO_Binary = crate::macho::binary::ffi::MachO_Binary;
        type MachO_FatBinary = crate::macho::fat_binary::ffi::MachO_FatBinary;
        type MachO_Utils;

        #[Self = "MachO_Utils"]
        fn is_macho(file: &CxxString) -> bool;
        #[Self = "MachO_Utils"]
        fn is_fat(file: &CxxString) -> bool;
        #[Self = "MachO_Utils"]
        fn is_64(file: &CxxString) -> bool;
        #[Self = "MachO_Utils"]
        unsafe fn check_layout(bin: &MachO_Binary, error: *mut CxxString) -> bool;
        #[Self = "MachO_Utils"]
        unsafe fn check_layout_fat(bin: &MachO_FatBinary, error: *mut CxxString) -> bool;
    }
}
