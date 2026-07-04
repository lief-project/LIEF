#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/Relocation.hpp");

        type PE_RelocationEntry = crate::pe::relocation_entry::ffi::PE_RelocationEntry;

        type PE_Relocation;

        fn virtual_address(self: &PE_Relocation) -> u32;
        fn block_size(self: &PE_Relocation) -> u32;
        fn entries(self: &PE_Relocation) -> UniquePtr<PE_Relocation_it_entries>;

        type PE_Relocation_it_entries;

        fn next(self: Pin<&mut PE_Relocation_it_entries>) -> UniquePtr<PE_RelocationEntry>;
        fn size(self: &PE_Relocation_it_entries) -> u64;
    }

    impl UniquePtr<PE_Relocation> {}
    impl UniquePtr<PE_Relocation_it_entries> {}
}
