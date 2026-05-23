#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/types/Subroutine.hpp");

        type DWARF_Parameter = crate::dwarf::parameter::ffi::DWARF_Parameter;
        type DWARF_Type = crate::dwarf::type_::ffi::DWARF_Type;

        type DWARF_types_Subroutine;

        #[Self = "DWARF_types_Subroutine"]
        fn classof(type_: &DWARF_Type) -> bool;
        fn return_type(self: &DWARF_types_Subroutine) -> UniquePtr<DWARF_Type>;
        fn parameters(
            self: &DWARF_types_Subroutine,
        ) -> UniquePtr<DWARF_types_Subroutine_it_parameters>;

        type DWARF_types_Subroutine_it_parameters;

        fn next(self: Pin<&mut DWARF_types_Subroutine_it_parameters>)
            -> UniquePtr<DWARF_Parameter>;
        fn size(self: &DWARF_types_Subroutine_it_parameters) -> u64;
    }
    impl UniquePtr<DWARF_types_Subroutine> {}
    impl UniquePtr<DWARF_types_Subroutine_it_parameters> {}
}
