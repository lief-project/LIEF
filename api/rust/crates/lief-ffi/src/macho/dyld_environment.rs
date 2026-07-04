#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/DyldEnvironment.hpp");

        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_DyldEnvironment;

        #[Self = "MachO_DyldEnvironment"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn value(self: &MachO_DyldEnvironment) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<MachO_DyldEnvironment> {}
}
