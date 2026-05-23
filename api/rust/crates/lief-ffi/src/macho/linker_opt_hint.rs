#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/LinkerOptHint.hpp");

        type Span = crate::utils::ffi::Span;
        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_LinkerOptHint;

        fn content(self: &MachO_LinkerOptHint) -> Span;
        #[Self = "MachO_LinkerOptHint"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn data_offset(self: &MachO_LinkerOptHint) -> u32;
        fn data_size(self: &MachO_LinkerOptHint) -> u32;
    }

    impl UniquePtr<MachO_LinkerOptHint> {}
}
