#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/types/Coarray.hpp");

        type DWARF_Type = crate::dwarf::type_::ffi::DWARF_Type;

        type DWARF_types_Coarray;

        #[Self = "DWARF_types_Coarray"]
        fn classof(type_: &DWARF_Type) -> bool;
    }
    impl UniquePtr<DWARF_types_Coarray> {}
}
