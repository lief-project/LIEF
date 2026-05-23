#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/NoteAndroidIdent.hpp");

        type ELF_Note = crate::elf::note::ffi::ELF_Note;

        type ELF_AndroidIdent;

        #[Self = "ELF_AndroidIdent"]
        fn classof(note: &ELF_Note) -> bool;
        fn sdk_version(self: &ELF_AndroidIdent) -> u32;
        fn ndk_version(self: &ELF_AndroidIdent) -> UniquePtr<CxxString>;
        fn ndk_build_number(self: &ELF_AndroidIdent) -> UniquePtr<CxxString>;
    }
    impl UniquePtr<ELF_AndroidIdent> {}
}
