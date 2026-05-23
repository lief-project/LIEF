#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/SubClient.hpp");

        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_SubClient;

        #[Self = "MachO_SubClient"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn client(self: &MachO_SubClient) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<MachO_SubClient> {}
}
