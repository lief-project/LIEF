#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/types/Base.hpp");

        type DWARF_Type = crate::dwarf::type_::ffi::DWARF_Type;

        type DWARF_types_Base;

        #[Self = "DWARF_types_Base"]
        fn classof(type_: &DWARF_Type) -> bool;
        fn encoding(self: &DWARF_types_Base) -> u32;
    }
    impl UniquePtr<DWARF_types_Base> {}
}
