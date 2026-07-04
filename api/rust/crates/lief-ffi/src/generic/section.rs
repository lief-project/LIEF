#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/Abstract/Section.hpp");

        type Span = crate::utils::ffi::Span;
        type AbstractSection;

        fn name(self: &AbstractSection) -> UniquePtr<CxxString>;
        fn content(self: &AbstractSection) -> Span;
        fn size(self: &AbstractSection) -> u64;
        fn offset(self: &AbstractSection) -> u64;
        fn virtual_address(self: &AbstractSection) -> u64;
        fn set_name(self: Pin<&mut AbstractSection>, name: &CxxString);
        fn set_size(self: Pin<&mut AbstractSection>, size: u64);
        unsafe fn set_content(self: Pin<&mut AbstractSection>, buffer: *const u8, size: usize);
    }
}
