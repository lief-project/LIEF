#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/CoreFile.hpp");

        type ELF_Note = crate::elf::note::ffi::ELF_Note;

        type ELF_CoreFile;

        #[Self = "ELF_CoreFile"]
        fn classof(note: &ELF_Note) -> bool;
        fn count(self: &ELF_CoreFile) -> u64;
        fn files(self: &ELF_CoreFile) -> UniquePtr<ELF_CoreFile_it_files>;

        type ELF_CoreFile_entry;

        fn start(self: &ELF_CoreFile_entry) -> u64;
        fn end(self: &ELF_CoreFile_entry) -> u64;
        fn path(self: &ELF_CoreFile_entry) -> UniquePtr<CxxString>;
        fn file_ofs(self: &ELF_CoreFile_entry) -> u64;

        type ELF_CoreFile_it_files;

        fn next(self: Pin<&mut ELF_CoreFile_it_files>) -> UniquePtr<ELF_CoreFile_entry>;
        fn size(self: &ELF_CoreFile_it_files) -> u64;
    }
    impl UniquePtr<ELF_CoreFile> {}
    impl UniquePtr<ELF_CoreFile_entry> {}
    impl UniquePtr<ELF_CoreFile_it_files> {}
}
