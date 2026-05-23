#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/COFF/String.hpp");

        type COFF_String;

        fn str(self: &COFF_String) -> UniquePtr<CxxString>;
        fn offset(self: &COFF_String) -> u32;
    }

    impl UniquePtr<COFF_String> {}
}
