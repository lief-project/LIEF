#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/types/RValueRef.hpp");

        type DWARF_Type = crate::dwarf::type_::ffi::DWARF_Type;

        type DWARF_types_RValueReference;

        #[Self = "DWARF_types_RValueReference"]
        fn classof(type_: &DWARF_Type) -> bool;
        fn underlying_type(self: &DWARF_types_RValueReference) -> UniquePtr<DWARF_Type>;
    }
    impl UniquePtr<DWARF_types_RValueReference> {}
}
