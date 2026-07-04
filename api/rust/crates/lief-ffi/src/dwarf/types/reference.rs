#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/types/Reference.hpp");

        type DWARF_Type = crate::dwarf::type_::ffi::DWARF_Type;

        type DWARF_types_Reference;

        #[Self = "DWARF_types_Reference"]
        fn classof(type_: &DWARF_Type) -> bool;
        fn underlying_type(self: &DWARF_types_Reference) -> UniquePtr<DWARF_Type>;
    }
    impl UniquePtr<DWARF_types_Reference> {}
}
