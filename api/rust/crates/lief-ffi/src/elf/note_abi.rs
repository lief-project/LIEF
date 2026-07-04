#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/NoteAbi.hpp");

        type ELF_Note = crate::elf::note::ffi::ELF_Note;

        type ELF_NoteAbi;

        #[Self = "ELF_NoteAbi"]
        fn classof(note: &ELF_Note) -> bool;
        fn abi(self: &ELF_NoteAbi) -> u32;
        fn version(self: &ELF_NoteAbi) -> UniquePtr<CxxVector<u64>>;
    }
    impl UniquePtr<ELF_NoteAbi> {}
}
