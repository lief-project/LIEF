#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/COFF/Header.hpp");

        type Span = crate::utils::ffi::Span;
        type COFF_BigObjHeader;

        fn uuid(self: &COFF_BigObjHeader) -> Span;
        #[Self = "COFF_BigObjHeader"]
        fn classof(hdr: &COFF_Header) -> bool;
        fn version(self: &COFF_BigObjHeader) -> u16;
        fn sizeof_data(self: &COFF_BigObjHeader) -> u32;
        fn flags(self: &COFF_BigObjHeader) -> u32;
        fn metadata_size(self: &COFF_BigObjHeader) -> u32;
        fn metadata_offset(self: &COFF_BigObjHeader) -> u32;

        type COFF_Header;

        fn machine(self: &COFF_Header) -> u32;
        fn nb_sections(self: &COFF_Header) -> u32;
        fn pointerto_symbol_table(self: &COFF_Header) -> u32;
        fn nb_symbols(self: &COFF_Header) -> u32;
        fn timedatestamp(self: &COFF_Header) -> u32;
        fn to_string(self: &COFF_Header) -> UniquePtr<CxxString>;

        type COFF_RegularHeader;

        #[Self = "COFF_RegularHeader"]
        fn classof(hdr: &COFF_Header) -> bool;
        fn sizeof_optionalheader(self: &COFF_RegularHeader) -> u16;
        fn characteristics(self: &COFF_RegularHeader) -> u16;
    }

    impl UniquePtr<COFF_Header> {}
    impl UniquePtr<COFF_BigObjHeader> {}
    impl UniquePtr<COFF_RegularHeader> {}
}
