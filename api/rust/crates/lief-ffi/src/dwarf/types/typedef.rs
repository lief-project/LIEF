#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/types/Typedef.hpp");

        type DWARF_Type = crate::dwarf::type_::ffi::DWARF_Type;

        type DWARF_types_Typedef;

        #[Self = "DWARF_types_Typedef"]
        fn classof(type_: &DWARF_Type) -> bool;
        fn underlying_type(self: &DWARF_types_Typedef) -> UniquePtr<DWARF_Type>;
    }
    impl UniquePtr<DWARF_types_Typedef> {}
}
