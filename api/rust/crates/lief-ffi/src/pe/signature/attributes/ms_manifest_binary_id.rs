#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/attributes/MsManifestBinaryID.hpp");

        type PE_Attribute = crate::pe::signature::attributes::attribute::ffi::PE_Attribute;

        type PE_MsManifestBinaryID;
        #[Self = "PE_MsManifestBinaryID"]
        fn classof(attr: &PE_Attribute) -> bool;

        fn manifest_id(self: &PE_MsManifestBinaryID) -> UniquePtr<CxxString>;
    }
    impl UniquePtr<PE_MsManifestBinaryID> {}
}
