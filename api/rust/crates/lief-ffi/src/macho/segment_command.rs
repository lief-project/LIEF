#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/SegmentCommand.hpp");

        type Span = crate::utils::ffi::Span;
        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;
        type MachO_Relocation = crate::macho::relocation::ffi::MachO_Relocation;
        type MachO_Section = crate::macho::section::ffi::MachO_Section;

        type MachO_SegmentCommand;

        fn content(self: &MachO_SegmentCommand) -> Span;
        #[Self = "MachO_SegmentCommand"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn name(self: &MachO_SegmentCommand) -> UniquePtr<CxxString>;
        fn virtual_address(self: &MachO_SegmentCommand) -> u64;
        fn virtual_size(self: &MachO_SegmentCommand) -> u64;
        fn file_size(self: &MachO_SegmentCommand) -> u64;
        fn file_offset(self: &MachO_SegmentCommand) -> u64;
        fn max_protection(self: &MachO_SegmentCommand) -> u32;
        fn init_protection(self: &MachO_SegmentCommand) -> u32;
        fn numberof_sections(self: &MachO_SegmentCommand) -> u32;
        fn flags(self: &MachO_SegmentCommand) -> u32;
        fn sections(self: &MachO_SegmentCommand) -> UniquePtr<MachO_SegmentCommand_it_sections>;
        fn relocations(
            self: &MachO_SegmentCommand,
        ) -> UniquePtr<MachO_SegmentCommand_it_relocations>;
        fn index(self: &MachO_SegmentCommand) -> i8;
        fn get_section(self: &MachO_SegmentCommand, name: &CxxString) -> UniquePtr<MachO_Section>;

        type MachO_SegmentCommand_it_relocations;

        fn next(self: Pin<&mut MachO_SegmentCommand_it_relocations>)
            -> UniquePtr<MachO_Relocation>;
        fn size(self: &MachO_SegmentCommand_it_relocations) -> u64;

        type MachO_SegmentCommand_it_sections;

        fn next(self: Pin<&mut MachO_SegmentCommand_it_sections>) -> UniquePtr<MachO_Section>;
        fn size(self: &MachO_SegmentCommand_it_sections) -> u64;
    }

    impl UniquePtr<MachO_SegmentCommand> {}
    impl UniquePtr<MachO_SegmentCommand_it_relocations> {}
    impl UniquePtr<MachO_SegmentCommand_it_sections> {}
}
