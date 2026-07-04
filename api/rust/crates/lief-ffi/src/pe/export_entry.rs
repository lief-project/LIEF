#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/ExportEntry.hpp");

        type PE_ExportEntry;

        #[Self = "PE_ExportEntry"]
        fn create() -> UniquePtr<PE_ExportEntry>;
        #[Self = "PE_ExportEntry"]
        fn create_with_name(name: &CxxString, addr: u32) -> UniquePtr<PE_ExportEntry>;
        fn ordinal(self: &PE_ExportEntry) -> u16;
        fn address(self: &PE_ExportEntry) -> u32;
        fn is_extern(self: &PE_ExportEntry) -> bool;
        fn is_forwarded(self: &PE_ExportEntry) -> bool;
        fn function_rva(self: &PE_ExportEntry) -> u32;
        fn fwd_library(self: &PE_ExportEntry) -> UniquePtr<CxxString>;
        fn fwd_function(self: &PE_ExportEntry) -> UniquePtr<CxxString>;
        fn set_address(self: Pin<&mut PE_ExportEntry>, addr: u32);
        fn demangled_name(self: &PE_ExportEntry) -> UniquePtr<CxxString>;
        fn set_ordinal(self: Pin<&mut PE_ExportEntry>, ordinal: u16);
    }
    impl UniquePtr<PE_ExportEntry> {}
}
