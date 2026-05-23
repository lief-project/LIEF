#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/Type.hpp");

        type DWARF_Scope = crate::dwarf::scope::ffi::DWARF_Scope;
        type DebugLocation = crate::debug_location::ffi::DebugLocation;
        type LIEF_DeclOpt = crate::debug_decl_opt::ffi::LIEF_DeclOpt;

        type DWARF_Type;

        fn name(self: &DWARF_Type, err: Pin<&mut u32>) -> UniquePtr<CxxString>;
        fn size(self: &DWARF_Type, err: Pin<&mut u32>) -> u64;
        fn location(self: &DWARF_Type) -> UniquePtr<DebugLocation>;
        fn is_unspecified(self: &DWARF_Type) -> bool;
        fn scope(self: &DWARF_Type) -> UniquePtr<DWARF_Scope>;
        fn to_decl(self: &DWARF_Type) -> UniquePtr<CxxString>;
        fn to_decl_with_opt(self: &DWARF_Type, opt: &LIEF_DeclOpt) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<DWARF_Type> {}
}
