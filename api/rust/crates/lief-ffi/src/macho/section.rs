#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/Section.hpp");
        include!("LIEF/rust/MachO/Relocation.hpp");

        type MachO_Relocation = crate::macho::relocation::ffi::MachO_Relocation;
        type MachO_SegmentCommand = crate::macho::segment_command::ffi::MachO_SegmentCommand;

        type MachO_Section;

        fn segment_name(self: &MachO_Section) -> UniquePtr<CxxString>;
        fn address(self: &MachO_Section) -> u64;
        fn alignment(self: &MachO_Section) -> u32;
        fn relocation_offset(self: &MachO_Section) -> u32;
        fn numberof_relocations(self: &MachO_Section) -> u32;
        fn flags(self: &MachO_Section) -> u64;
        fn reserved1(self: &MachO_Section) -> u32;
        fn reserved2(self: &MachO_Section) -> u32;
        fn reserved3(self: &MachO_Section) -> u32;
        fn raw_flags(self: &MachO_Section) -> u32;
        fn segment(self: &MachO_Section) -> UniquePtr<MachO_SegmentCommand>;
        fn relocations(self: &MachO_Section) -> UniquePtr<MachO_Section_it_relocations>;
        fn has_segment(self: &MachO_Section) -> bool;
        fn section_type(self: &MachO_Section) -> u64;

        type MachO_Section_it_relocations;

        fn next(self: Pin<&mut MachO_Section_it_relocations>) -> UniquePtr<MachO_Relocation>;
        fn size(self: &MachO_Section_it_relocations) -> u64;
    }

    impl UniquePtr<MachO_Section> {}
    impl UniquePtr<MachO_Section_it_relocations> {}
}
