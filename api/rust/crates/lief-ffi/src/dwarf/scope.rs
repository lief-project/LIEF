#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/Scope.hpp");

        type DWARF_Scope;

        fn name(self: &DWARF_Scope) -> UniquePtr<CxxString>;
        fn parent(self: &DWARF_Scope) -> UniquePtr<DWARF_Scope>;
        fn get_type(self: &DWARF_Scope) -> u32;
        fn chained(self: &DWARF_Scope, sep: &CxxString) -> UniquePtr<CxxString>;
    }
    impl UniquePtr<DWARF_Scope> {}
}
