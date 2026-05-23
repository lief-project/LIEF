#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/debug/Repro.hpp");

        type Span = crate::utils::ffi::Span;
        type PE_Debug = crate::pe::debug::debug::ffi::PE_Debug;

        type PE_Repro;

        fn hash(self: &PE_Repro) -> Span;
        #[Self = "PE_Repro"]
        fn classof(entry: &PE_Debug) -> bool;
    }
    impl UniquePtr<PE_Repro> {}
}
