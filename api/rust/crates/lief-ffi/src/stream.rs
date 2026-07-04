#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/Stream.hpp");

        type COFF_Binary = crate::coff::binary::ffi::COFF_Binary;
        type ELF_Binary = crate::elf::binary::ffi::ELF_Binary;
        type MachO_FatBinary = crate::macho::fat_binary::ffi::MachO_FatBinary;
        type PE_Binary = crate::pe::binary::ffi::PE_Binary;

        type RustStream;

        #[Self = "RustStream"]
        unsafe fn from_rust(buffer: *mut u8, size: usize) -> UniquePtr<RustStream>;
        fn is_elf(self: &RustStream) -> bool;
        fn is_pe(self: &RustStream) -> bool;
        fn is_macho(self: &RustStream) -> bool;
        fn is_coff(self: &RustStream) -> bool;
        fn as_elf(self: Pin<&mut RustStream>) -> UniquePtr<ELF_Binary>;
        fn as_macho(self: Pin<&mut RustStream>) -> UniquePtr<MachO_FatBinary>;
        fn as_pe(self: Pin<&mut RustStream>) -> UniquePtr<PE_Binary>;
        fn as_coff(self: Pin<&mut RustStream>) -> UniquePtr<COFF_Binary>;
    }
}
