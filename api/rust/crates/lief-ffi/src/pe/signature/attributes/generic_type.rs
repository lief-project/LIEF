#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/attributes/GenericType.hpp");

        type Span = crate::utils::ffi::Span;
        type PE_Attribute = crate::pe::signature::attributes::attribute::ffi::PE_Attribute;

        type PE_GenericType;
        fn raw_content(self: &PE_GenericType) -> Span;
        #[Self = "PE_GenericType"]
        fn classof(attr: &PE_Attribute) -> bool;

        fn oid(self: &PE_GenericType) -> UniquePtr<CxxString>;
    }
    impl UniquePtr<PE_GenericType> {}
}
