#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/types/SetTy.hpp");

        type DWARF_Type = crate::dwarf::type_::ffi::DWARF_Type;

        type DWARF_types_SetTy;

        #[Self = "DWARF_types_SetTy"]
        fn classof(type_: &DWARF_Type) -> bool;
        fn underlying_type(self: &DWARF_types_SetTy) -> UniquePtr<DWARF_Type>;
    }
    impl UniquePtr<DWARF_types_SetTy> {}
}
