#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/BindingInfo.hpp");

        type MachO_Dylib = crate::macho::dylib::ffi::MachO_Dylib;
        type MachO_SegmentCommand = crate::macho::segment_command::ffi::MachO_SegmentCommand;
        type MachO_Symbol = crate::macho::symbol::ffi::MachO_Symbol;

        type MachO_BindingInfo;

        fn address(self: &MachO_BindingInfo) -> u64;
        fn addend(self: &MachO_BindingInfo) -> i64;
        fn library_ordinal(self: &MachO_BindingInfo) -> i32;
        fn library(self: &MachO_BindingInfo) -> UniquePtr<MachO_Dylib>;
        fn symbol(self: &MachO_BindingInfo) -> UniquePtr<MachO_Symbol>;
        fn segment(self: &MachO_BindingInfo) -> UniquePtr<MachO_SegmentCommand>;
    }

    impl UniquePtr<MachO_BindingInfo> {}
}
