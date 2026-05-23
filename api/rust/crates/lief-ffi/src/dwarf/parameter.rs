#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/Parameter.hpp");

        type DWARF_Type = crate::dwarf::type_::ffi::DWARF_Type;

        type DWARF_Parameter;

        fn name(self: &DWARF_Parameter) -> UniquePtr<CxxString>;
        fn get_type(self: &DWARF_Parameter) -> UniquePtr<DWARF_Type>;
        fn location(self: &DWARF_Parameter) -> UniquePtr<DWARF_Parameter_Location>;

        type DWARF_Parameter_Location;

        fn get_type(self: &DWARF_Parameter_Location) -> u8;

        type DWARF_Parameter_RegisterLocation;

        #[Self = "DWARF_Parameter_RegisterLocation"]
        fn classof(loc: &DWARF_Parameter_Location) -> bool;
        fn id(self: &DWARF_Parameter_RegisterLocation) -> u64;

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
    impl UniquePtr<DWARF_Parameter_Location> {}
    impl UniquePtr<DWARF_Parameter_RegisterLocation> {}
    impl UniquePtr<DWARF_parameters_Formal> {}
    impl UniquePtr<DWARF_parameters_TemplateType> {}
    impl UniquePtr<DWARF_parameters_TemplateValue> {}
}
