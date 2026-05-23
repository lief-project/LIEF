#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/ResourceIcon.hpp");

        type Span = crate::utils::ffi::Span;
        type PE_ResourceIcon;

        fn pixels(self: &PE_ResourceIcon) -> Span;
        fn id(self: &PE_ResourceIcon) -> u32;
        fn lang(self: &PE_ResourceIcon) -> u32;
        fn sublang(self: &PE_ResourceIcon) -> u32;
        fn width(self: &PE_ResourceIcon) -> u8;
        fn height(self: &PE_ResourceIcon) -> u8;
        fn color_count(self: &PE_ResourceIcon) -> u8;
        fn reserved(self: &PE_ResourceIcon) -> u8;
        fn planes(self: &PE_ResourceIcon) -> u16;
        fn bit_count(self: &PE_ResourceIcon) -> u16;
        fn size(self: &PE_ResourceIcon) -> u32;
    }

    impl UniquePtr<PE_ResourceIcon> {}
}
