#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/DataCodeEntry.hpp");

        type MachO_DataCodeEntry;

        fn offset(self: &MachO_DataCodeEntry) -> u32;
        fn length(self: &MachO_DataCodeEntry) -> u32;
        fn get_type(self: &MachO_DataCodeEntry) -> u32;
    }

    impl UniquePtr<MachO_DataCodeEntry> {}
}
