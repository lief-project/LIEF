#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/Dylinker.hpp");

        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_Dylinker;

        #[Self = "MachO_Dylinker"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn name(self: &MachO_Dylinker) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<MachO_Dylinker> {}
}
