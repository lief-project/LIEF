#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/types/PointerToMember.hpp");

        type DWARF_Type = crate::dwarf::type_::ffi::DWARF_Type;

        type DWARF_types_PointerToMember;

        #[Self = "DWARF_types_PointerToMember"]
        fn classof(type_: &DWARF_Type) -> bool;
        fn underlying_type(self: &DWARF_types_PointerToMember) -> UniquePtr<DWARF_Type>;
        fn containing_type(self: &DWARF_types_PointerToMember) -> UniquePtr<DWARF_Type>;
    }
    impl UniquePtr<DWARF_types_PointerToMember> {}
}
