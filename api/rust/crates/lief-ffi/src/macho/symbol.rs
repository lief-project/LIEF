#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/Symbol.hpp");
        include!("LIEF/rust/MachO/ExportInfo.hpp");
        include!("LIEF/rust/MachO/BindingInfo.hpp");

        type MachO_BindingInfo = crate::macho::binding_info::ffi::MachO_BindingInfo;
        type MachO_Dylib = crate::macho::dylib::ffi::MachO_Dylib;
        type MachO_ExportInfo = crate::macho::export_info::ffi::MachO_ExportInfo;

        type MachO_Symbol;

        fn get_type(self: &MachO_Symbol) -> u8;
        fn numberof_sections(self: &MachO_Symbol) -> u8;
        fn description(self: &MachO_Symbol) -> u16;
        fn origin(self: &MachO_Symbol) -> u32;
        fn category(self: &MachO_Symbol) -> u32;
        fn is_external(self: &MachO_Symbol) -> bool;
        fn demangled_name(self: &MachO_Symbol) -> UniquePtr<CxxString>;
        fn export_info(self: &MachO_Symbol) -> UniquePtr<MachO_ExportInfo>;
        fn binding_info(self: &MachO_Symbol) -> UniquePtr<MachO_BindingInfo>;
        fn library(self: &MachO_Symbol) -> UniquePtr<MachO_Dylib>;
        fn library_ordinal(self: &MachO_Symbol) -> i32;
    }

    impl UniquePtr<MachO_Symbol> {}
}
