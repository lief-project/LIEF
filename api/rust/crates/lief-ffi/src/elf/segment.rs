#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/Segment.hpp");

        type Span = crate::utils::ffi::Span;
        type ELF_Segment;

        fn content(self: &ELF_Segment) -> Span;
        #[Self = "ELF_Segment"]
        fn create() -> UniquePtr<ELF_Segment>;
        fn flags(self: &ELF_Segment) -> u32;
        fn file_offset(self: &ELF_Segment) -> u64;
        fn virtual_address(self: &ELF_Segment) -> u64;
        fn physical_address(self: &ELF_Segment) -> u64;
        fn physical_size(self: &ELF_Segment) -> u64;
        fn virtual_size(self: &ELF_Segment) -> u64;
        fn alignment(self: &ELF_Segment) -> u64;
        fn set_type(self: Pin<&mut ELF_Segment>, ty: u64);
        fn fill(self: Pin<&mut ELF_Segment>, c: i8);
        fn clear(self: Pin<&mut ELF_Segment>);
        fn to_string(self: &ELF_Segment) -> UniquePtr<CxxString>;
        fn stype(self: &ELF_Segment) -> u64;
        fn set_flags(self: Pin<&mut ELF_Segment>, value: u32);
        fn set_file_offset(self: Pin<&mut ELF_Segment>, value: u64);
        fn set_virtual_address(self: Pin<&mut ELF_Segment>, value: u64);
        fn set_physical_address(self: Pin<&mut ELF_Segment>, value: u64);
        fn set_virtual_size(self: Pin<&mut ELF_Segment>, value: u64);
        fn set_alignment(self: Pin<&mut ELF_Segment>, value: u64);
        unsafe fn set_content(self: Pin<&mut ELF_Segment>, ptr: *const u8, size: u64);
    }
    impl UniquePtr<ELF_Segment> {}
}
