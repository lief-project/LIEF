#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/utils.hpp");
        include!("LIEF/rust/COFF/Section.hpp");

        type PE_Binary = crate::pe::binary::ffi::PE_Binary;
        type PE_Import = crate::pe::import::ffi::PE_Import;

        type PE_Utils;

        #[Self = "PE_Utils"]
        fn is_pe(file: &CxxString) -> bool;
        #[Self = "PE_Utils"]
        fn get_type(file: &CxxString) -> u32;
        #[Self = "PE_Utils"]
        fn get_imphash(bin: &PE_Binary, mode: u32) -> UniquePtr<CxxString>;
        #[Self = "PE_Utils"]
        fn oid_to_string(oid: &CxxString) -> UniquePtr<CxxString>;
        #[Self = "PE_Utils"]
        fn resolve_ordinals(imp: &PE_Import, strict: bool, use_std: bool) -> UniquePtr<PE_Import>;
        #[Self = "PE_Utils"]
        unsafe fn check_layout(bin: &PE_Binary, error: *mut CxxString) -> bool;
    }
}
