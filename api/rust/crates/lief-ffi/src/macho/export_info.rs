#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/ExportInfo.hpp");

        type MachO_Dylib = crate::macho::dylib::ffi::MachO_Dylib;
        type MachO_Symbol = crate::macho::symbol::ffi::MachO_Symbol;

        type MachO_ExportInfo;

        fn node_offset(self: &MachO_ExportInfo) -> u64;
        fn flags(self: &MachO_ExportInfo) -> u64;
        fn address(self: &MachO_ExportInfo) -> u64;
        fn other(self: &MachO_ExportInfo) -> u64;
        fn kind(self: &MachO_ExportInfo) -> u64;
        fn symbol(self: &MachO_ExportInfo) -> UniquePtr<MachO_Symbol>;
        fn alias(self: &MachO_ExportInfo) -> UniquePtr<MachO_Symbol>;
        fn alias_library(self: &MachO_ExportInfo) -> UniquePtr<MachO_Dylib>;
    }

    impl UniquePtr<MachO_ExportInfo> {}
}
