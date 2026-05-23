#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/Relocation.hpp");

        type MachO_Section = crate::macho::section::ffi::MachO_Section;
        type MachO_SegmentCommand = crate::macho::segment_command::ffi::MachO_SegmentCommand;
        type MachO_Symbol = crate::macho::symbol::ffi::MachO_Symbol;

        type MachO_Relocation;

        fn is_pc_relative(self: &MachO_Relocation) -> bool;
        fn architecture(self: &MachO_Relocation) -> u32;
        fn origin(self: &MachO_Relocation) -> u32;
        fn symbol(self: &MachO_Relocation) -> UniquePtr<MachO_Symbol>;
        fn section(self: &MachO_Relocation) -> UniquePtr<MachO_Section>;
        fn segment(self: &MachO_Relocation) -> UniquePtr<MachO_SegmentCommand>;
    }

    impl UniquePtr<MachO_Relocation> {}
}
