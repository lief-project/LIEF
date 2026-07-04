#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/Header.hpp");

        type MachO_Header;

        fn magic(self: &MachO_Header) -> u32;
        fn cpu_type(self: &MachO_Header) -> i32;
        fn cpu_subtype(self: &MachO_Header) -> u32;
        fn file_type(self: &MachO_Header) -> u32;
        fn nb_cmds(self: &MachO_Header) -> u32;
        fn sizeof_cmds(self: &MachO_Header) -> u32;
        fn flags(self: &MachO_Header) -> u32;
        fn reserved(self: &MachO_Header) -> u32;
        fn is_32bit(self: &MachO_Header) -> bool;
        fn is_64bit(self: &MachO_Header) -> bool;
    }

    impl UniquePtr<MachO_Header> {}
}
