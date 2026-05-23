#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/types/TemplateAlias.hpp");

        type DWARF_Parameter = crate::dwarf::parameter::ffi::DWARF_Parameter;
        type DWARF_Type = crate::dwarf::type_::ffi::DWARF_Type;

        type DWARF_types_TemplateAlias;

        #[Self = "DWARF_types_TemplateAlias"]
        fn classof(type_: &DWARF_Type) -> bool;
        fn underlying_type(self: &DWARF_types_TemplateAlias) -> UniquePtr<DWARF_Type>;
        fn parameters(
            self: &DWARF_types_TemplateAlias,
        ) -> UniquePtr<DWARF_types_TemplateAlias_it_parameters>;

        type DWARF_types_TemplateAlias_it_parameters;

        fn next(
            self: Pin<&mut DWARF_types_TemplateAlias_it_parameters>,
        ) -> UniquePtr<DWARF_Parameter>;
        fn size(self: &DWARF_types_TemplateAlias_it_parameters) -> u64;
    }
    impl UniquePtr<DWARF_types_TemplateAlias> {}
    impl UniquePtr<DWARF_types_TemplateAlias_it_parameters> {}
}
