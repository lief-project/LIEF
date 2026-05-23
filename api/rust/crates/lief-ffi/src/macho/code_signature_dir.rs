#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/CodeSignatureDir.hpp");

        type Span = crate::utils::ffi::Span;
        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_CodeSignatureDir;

        fn content(self: &MachO_CodeSignatureDir) -> Span;
        #[Self = "MachO_CodeSignatureDir"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn data_offset(self: &MachO_CodeSignatureDir) -> u32;
        fn data_size(self: &MachO_CodeSignatureDir) -> u32;
    }

    impl UniquePtr<MachO_CodeSignatureDir> {}
}
