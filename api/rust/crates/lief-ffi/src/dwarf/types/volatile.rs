#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/types/Volatile.hpp");

        type DWARF_Type = crate::dwarf::type_::ffi::DWARF_Type;

        type DWARF_types_Volatile;

        #[Self = "DWARF_types_Volatile"]
        fn classof(type_: &DWARF_Type) -> bool;
        fn underlying_type(self: &DWARF_types_Volatile) -> UniquePtr<DWARF_Type>;
    }
    impl UniquePtr<DWARF_types_Volatile> {}
}
