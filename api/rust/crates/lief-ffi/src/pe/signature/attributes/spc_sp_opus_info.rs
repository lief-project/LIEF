#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/attributes/SpcSpOpusInfo.hpp");

        type PE_Attribute = crate::pe::signature::attributes::attribute::ffi::PE_Attribute;

        type PE_SpcSpOpusInfo;
        #[Self = "PE_SpcSpOpusInfo"]
        fn classof(attr: &PE_Attribute) -> bool;

        fn program_name(self: &PE_SpcSpOpusInfo) -> UniquePtr<CxxString>;
        fn more_info(self: &PE_SpcSpOpusInfo) -> UniquePtr<CxxString>;
    }
    impl UniquePtr<PE_SpcSpOpusInfo> {}
}
