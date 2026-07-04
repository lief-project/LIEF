#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/DosHeader.hpp");

        type PE_DosHeader;

        fn magic(self: &PE_DosHeader) -> u16;
        fn used_bytes_in_last_page(self: &PE_DosHeader) -> u16;
        fn file_size_in_pages(self: &PE_DosHeader) -> u16;
        fn numberof_relocation(self: &PE_DosHeader) -> u16;
        fn header_size_in_paragraphs(self: &PE_DosHeader) -> u16;
        fn minimum_extra_paragraphs(self: &PE_DosHeader) -> u16;
        fn maximum_extra_paragraphs(self: &PE_DosHeader) -> u16;
        fn initial_relative_ss(self: &PE_DosHeader) -> u16;
        fn initial_sp(self: &PE_DosHeader) -> u16;
        fn checksum(self: &PE_DosHeader) -> u16;
        fn initial_ip(self: &PE_DosHeader) -> u16;
        fn initial_relative_cs(self: &PE_DosHeader) -> u16;
        fn addressof_relocation_table(self: &PE_DosHeader) -> u16;
        fn overlay_number(self: &PE_DosHeader) -> u16;
        fn reserved(self: &PE_DosHeader) -> UniquePtr<CxxVector<u64>>;
        fn oem_id(self: &PE_DosHeader) -> u16;
        fn oem_info(self: &PE_DosHeader) -> u16;
        fn reserved2(self: &PE_DosHeader) -> UniquePtr<CxxVector<u64>>;
        fn addressof_new_exeheader(self: &PE_DosHeader) -> u32;
    }

    impl UniquePtr<PE_DosHeader> {}
}
