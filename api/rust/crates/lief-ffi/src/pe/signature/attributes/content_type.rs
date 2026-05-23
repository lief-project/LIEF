#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/attributes/ContentType.hpp");

        type PE_Attribute = crate::pe::signature::attributes::attribute::ffi::PE_Attribute;

        type PE_ContentType;

        #[Self = "PE_ContentType"]
        fn classof(attr: &PE_Attribute) -> bool;
        fn oid(self: &PE_ContentType) -> UniquePtr<CxxString>;
    }
    impl UniquePtr<PE_ContentType> {}
}
