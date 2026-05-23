#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/AtomInfo.hpp");

        type Span = crate::utils::ffi::Span;
        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_AtomInfo;

        fn content(self: &MachO_AtomInfo) -> Span;
        #[Self = "MachO_AtomInfo"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn data_offset(self: &MachO_AtomInfo) -> u32;
        fn data_size(self: &MachO_AtomInfo) -> u32;
    }

    impl UniquePtr<MachO_AtomInfo> {}
}
