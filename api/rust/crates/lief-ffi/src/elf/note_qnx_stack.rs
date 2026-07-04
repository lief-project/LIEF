#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/NoteQNXStack.hpp");

        type ELF_Note = crate::elf::note::ffi::ELF_Note;

        type ELF_QNXStack;

        #[Self = "ELF_QNXStack"]
        fn classof(note: &ELF_Note) -> bool;
        fn stack_size(self: &ELF_QNXStack) -> u32;
        fn stack_allocated(self: &ELF_QNXStack) -> u32;
        fn is_executable(self: &ELF_QNXStack) -> bool;
    }
    impl UniquePtr<ELF_QNXStack> {}
}
