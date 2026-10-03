#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/Parameter.hpp");

        type DWARF_Type = crate::dwarf::type_::ffi::DWARF_Type;
        type DWARF_Location = crate::dwarf::location::ffi::DWARF_Location;
        type DWARF_it_locations = crate::dwarf::location::ffi::DWARF_it_locations;

        type DWARF_Parameter;

        fn name(self: &DWARF_Parameter) -> UniquePtr<CxxString>;
        fn get_type(self: &DWARF_Parameter) -> UniquePtr<DWARF_Type>;
        fn location(self: &DWARF_Parameter) -> UniquePtr<DWARF_Location>;
        fn location_at(self: &DWARF_Parameter, pc: u64) -> UniquePtr<DWARF_Location>;
        fn locations(self: &DWARF_Parameter) -> UniquePtr<DWARF_it_locations>;

        type DWARF_parameters_Formal;

        #[Self = "DWARF_parameters_Formal"]
        fn classof(type_: &DWARF_Parameter) -> bool;

        type DWARF_parameters_TemplateType;

        #[Self = "DWARF_parameters_TemplateType"]
        fn classof(type_: &DWARF_Parameter) -> bool;

        type DWARF_parameters_TemplateValue;

        #[Self = "DWARF_parameters_TemplateValue"]
        fn classof(type_: &DWARF_Parameter) -> bool;
    }

    impl UniquePtr<DWARF_Parameter> {}
    impl UniquePtr<DWARF_parameters_Formal> {}
    impl UniquePtr<DWARF_parameters_TemplateType> {}
    impl UniquePtr<DWARF_parameters_TemplateValue> {}
}
