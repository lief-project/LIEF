#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/Factory.hpp");
        include!("LIEF/rust/COFF/Section.hpp");

        type PE_Binary = crate::pe::binary::ffi::PE_Binary;
        type PE_Section = crate::pe::section::ffi::PE_Section;

        type PE_Factory;

        #[Self = "PE_Factory"]
        fn create(pe_type: u32) -> UniquePtr<PE_Factory>;
        fn set_arch(self: Pin<&mut PE_Factory>, arch: u32);
        fn set_entrypoint(self: Pin<&mut PE_Factory>, ep: u64);
        fn add_section(self: Pin<&mut PE_Factory>, section: &PE_Section);
        fn get(self: Pin<&mut PE_Factory>) -> UniquePtr<PE_Binary>;
        fn is_32bit(self: &PE_Factory) -> bool;
        fn is_64bit(self: &PE_Factory) -> bool;
        fn section_align(self: &PE_Factory) -> u32;
        fn file_align(self: &PE_Factory) -> u32;
    }
    impl UniquePtr<PE_Factory> {}
}
