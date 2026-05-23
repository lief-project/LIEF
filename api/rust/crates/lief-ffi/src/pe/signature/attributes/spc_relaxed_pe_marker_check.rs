#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/attributes/SpcRelaxedPeMarkerCheck.hpp");

        type PE_Attribute = crate::pe::signature::attributes::attribute::ffi::PE_Attribute;

        type PE_SpcRelaxedPeMarkerCheck;
        #[Self = "PE_SpcRelaxedPeMarkerCheck"]
        fn classof(attr: &PE_Attribute) -> bool;

        fn value(self: &PE_SpcRelaxedPeMarkerCheck) -> u32;
    }
    impl UniquePtr<PE_SpcRelaxedPeMarkerCheck> {}
}
