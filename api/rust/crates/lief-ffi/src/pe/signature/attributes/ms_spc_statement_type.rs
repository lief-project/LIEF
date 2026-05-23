#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/attributes/MsSpcStatementType.hpp");

        type PE_Attribute = crate::pe::signature::attributes::attribute::ffi::PE_Attribute;

        type PE_MsSpcStatementType;
        #[Self = "PE_MsSpcStatementType"]
        fn classof(attr: &PE_Attribute) -> bool;

        fn oid(self: &PE_MsSpcStatementType) -> UniquePtr<CxxString>;
    }
    impl UniquePtr<PE_MsSpcStatementType> {}
}
