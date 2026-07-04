#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/NoteCommand.hpp");

        type Span = crate::utils::ffi::Span;
        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_NoteCommand;

        #[Self = "MachO_NoteCommand"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn note_offset(self: &MachO_NoteCommand) -> u64;
        fn note_size(self: &MachO_NoteCommand) -> u64;
        fn owner(self: &MachO_NoteCommand) -> Span;
        fn set_note_offset(self: Pin<&mut MachO_NoteCommand>, value: u64);
        fn set_note_size(self: Pin<&mut MachO_NoteCommand>, value: u64);
    }

    impl UniquePtr<MachO_NoteCommand> {}
}
