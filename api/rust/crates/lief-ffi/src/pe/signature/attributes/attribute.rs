#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/attributes/Attribute.hpp");

        type PE_Attribute;
    }

    impl UniquePtr<PE_Attribute> {}
}
