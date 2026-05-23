#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/CodeSignature.hpp");

        type Span = crate::utils::ffi::Span;
        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_CodeSignature;

        fn content(self: &MachO_CodeSignature) -> Span;
        #[Self = "MachO_CodeSignature"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn data_offset(self: &MachO_CodeSignature) -> u32;
        fn data_size(self: &MachO_CodeSignature) -> u32;
    }

    impl UniquePtr<MachO_CodeSignature> {}
}
