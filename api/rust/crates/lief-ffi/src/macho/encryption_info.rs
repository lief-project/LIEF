#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/EncryptionInfo.hpp");

        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_EncryptionInfo;

        #[Self = "MachO_EncryptionInfo"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn crypt_offset(self: &MachO_EncryptionInfo) -> u32;
        fn crypt_size(self: &MachO_EncryptionInfo) -> u32;
        fn crypt_id(self: &MachO_EncryptionInfo) -> u32;
    }

    impl UniquePtr<MachO_EncryptionInfo> {}
}
