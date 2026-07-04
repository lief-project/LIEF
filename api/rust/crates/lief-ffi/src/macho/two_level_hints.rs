#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/TwoLevelHints.hpp");

        type Span = crate::utils::ffi::Span;
        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_TwoLevelHints;

        fn content(self: &MachO_TwoLevelHints) -> Span;
        #[Self = "MachO_TwoLevelHints"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn offset(self: &MachO_TwoLevelHints) -> u32;
        fn original_nb_hints(self: &MachO_TwoLevelHints) -> u32;
    }

    impl UniquePtr<MachO_TwoLevelHints> {}
}
