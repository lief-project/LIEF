#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/DynamicEntryRunPath.hpp");

        type ELF_DynamicEntry = crate::elf::dynamic_entry::ffi::ELF_DynamicEntry;

        type ELF_DynamicEntryRunPath;

        #[Self = "ELF_DynamicEntryRunPath"]
        fn create(name: &CxxString) -> UniquePtr<ELF_DynamicEntryRunPath>;
        #[Self = "ELF_DynamicEntryRunPath"]
        fn classof(entry: &ELF_DynamicEntry) -> bool;
        fn runpath(self: &ELF_DynamicEntryRunPath) -> UniquePtr<CxxString>;
        fn paths(self: &ELF_DynamicEntryRunPath) -> UniquePtr<CxxVector<CxxString>>;
        fn insert(self: Pin<&mut ELF_DynamicEntryRunPath>, pos: u32, name: &CxxString);
        fn append(self: Pin<&mut ELF_DynamicEntryRunPath>, name: &CxxString);
        fn remove(self: Pin<&mut ELF_DynamicEntryRunPath>, path: &CxxString);
        fn set_runpath(self: Pin<&mut ELF_DynamicEntryRunPath>, path: &CxxString);
    }
    impl UniquePtr<ELF_DynamicEntryRunPath> {}
}
