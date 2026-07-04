#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ObjC/Property.hpp");

        type ObjC_Property;

        fn name(self: &ObjC_Property) -> UniquePtr<CxxString>;
        fn attribute(self: &ObjC_Property) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<ObjC_Property> {}
}
