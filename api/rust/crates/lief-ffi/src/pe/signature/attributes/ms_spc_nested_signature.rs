#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/attributes/MsSpcNestedSignature.hpp");

        type PE_Signature = crate::pe::signature::signature::ffi::PE_Signature;

        type PE_Attribute = crate::pe::signature::attributes::attribute::ffi::PE_Attribute;

        type PE_MsSpcNestedSignature;
        #[Self = "PE_MsSpcNestedSignature"]
        fn classof(attr: &PE_Attribute) -> bool;

        fn sig(self: &PE_MsSpcNestedSignature) -> UniquePtr<PE_Signature>;
    }
    impl UniquePtr<PE_MsSpcNestedSignature> {}
}
