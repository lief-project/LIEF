#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/CoreSigInfo.hpp");

        type ELF_Note = crate::elf::note::ffi::ELF_Note;

        type ELF_CoreSigInfo;

        #[Self = "ELF_CoreSigInfo"]
        fn classof(note: &ELF_Note) -> bool;
        fn signo(self: &ELF_CoreSigInfo, err: Pin<&mut u32>) -> i32;
        fn sigcode(self: &ELF_CoreSigInfo, err: Pin<&mut u32>) -> i32;
        fn sigerrno(self: &ELF_CoreSigInfo, err: Pin<&mut u32>) -> i32;
    }
    impl UniquePtr<ELF_CoreSigInfo> {}
}
