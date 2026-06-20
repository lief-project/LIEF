#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DebugDeclOpt.hpp");

        type LIEF_DeclOpt;

        #[Self = "LIEF_DeclOpt"]
        fn create() -> UniquePtr<LIEF_DeclOpt>;
        fn set_indentation(self: Pin<&mut LIEF_DeclOpt>, value: u32);
        fn set_is_cpp(self: Pin<&mut LIEF_DeclOpt>, value: bool);
        fn set_show_extended_annotations(self: Pin<&mut LIEF_DeclOpt>, value: bool);
        fn set_include_types(self: Pin<&mut LIEF_DeclOpt>, value: bool);
        fn set_include_locals(self: Pin<&mut LIEF_DeclOpt>, value: bool);
        fn set_desugar(self: Pin<&mut LIEF_DeclOpt>, value: bool);
    }
    impl UniquePtr<LIEF_DeclOpt> {}
}
