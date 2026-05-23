#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/LoadCommand.hpp");

        type Span = crate::utils::ffi::Span;
        type MachO_Command;

        fn size(self: &MachO_Command) -> u32;
        fn command_offset(self: &MachO_Command) -> u64;
        fn cmd_type(self: &MachO_Command) -> u64;
        fn data(self: &MachO_Command) -> Span;
    }

    impl UniquePtr<MachO_Command> {}
}
