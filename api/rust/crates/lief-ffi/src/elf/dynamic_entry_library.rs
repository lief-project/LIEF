#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/DynamicEntryLibrary.hpp");

        type ELF_DynamicEntry = crate::elf::dynamic_entry::ffi::ELF_DynamicEntry;

        type ELF_DynamicEntryLibrary;

        #[Self = "ELF_DynamicEntryLibrary"]
        fn classof(entry: &ELF_DynamicEntry) -> bool;
        fn name(self: &ELF_DynamicEntryLibrary) -> UniquePtr<CxxString>;
        fn set_name(self: Pin<&mut ELF_DynamicEntryLibrary>, name: &CxxString);
    }

    impl UniquePtr<ELF_DynamicEntryLibrary> {}
}
