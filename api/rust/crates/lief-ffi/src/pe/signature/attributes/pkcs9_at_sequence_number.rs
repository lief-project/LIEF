#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/attributes/PKCS9AtSequenceNumber.hpp");

        type PE_Attribute = crate::pe::signature::attributes::attribute::ffi::PE_Attribute;

        type PE_PKCS9AtSequenceNumber;
        #[Self = "PE_PKCS9AtSequenceNumber"]
        fn classof(attr: &PE_Attribute) -> bool;

        fn number(self: &PE_PKCS9AtSequenceNumber) -> u32;
    }
    impl UniquePtr<PE_PKCS9AtSequenceNumber> {}
}
