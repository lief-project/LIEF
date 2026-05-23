#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/attributes/PKCS9SigningTime.hpp");

        type PE_Attribute = crate::pe::signature::attributes::attribute::ffi::PE_Attribute;

        type PE_PKCS9SigningTime;
        #[Self = "PE_PKCS9SigningTime"]
        fn classof(attr: &PE_Attribute) -> bool;

        fn time(self: &PE_PKCS9SigningTime) -> UniquePtr<CxxVector<u64>>;
    }
    impl UniquePtr<PE_PKCS9SigningTime> {}
}
