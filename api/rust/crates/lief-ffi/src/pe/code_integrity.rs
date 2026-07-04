#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/CodeIntegrity.hpp");

        type PE_CodeIntegrity;

        fn flags(self: &PE_CodeIntegrity) -> u16;
        fn catalog(self: &PE_CodeIntegrity) -> u16;
        fn catalog_offset(self: &PE_CodeIntegrity) -> u32;
        fn reserved(self: &PE_CodeIntegrity) -> u32;
    }

    impl UniquePtr<PE_CodeIntegrity> {}
}
