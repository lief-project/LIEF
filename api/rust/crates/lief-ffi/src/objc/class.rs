#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ObjC/Class.hpp");

        type ObjC_DeclOpt = crate::objc::decl_opt::ffi::ObjC_DeclOpt;
        type ObjC_IVar = crate::objc::i_var::ffi::ObjC_IVar;
        type ObjC_Method = crate::objc::method::ffi::ObjC_Method;
        type ObjC_Property = crate::objc::property::ffi::ObjC_Property;
        type ObjC_Protocol = crate::objc::protocol::ffi::ObjC_Protocol;

        type ObjC_Class;

        fn to_decl_with_opt(self: &ObjC_Class, opt: &ObjC_DeclOpt) -> UniquePtr<CxxString>;

        fn name(self: &ObjC_Class) -> UniquePtr<CxxString>;
        fn demangled_name(self: &ObjC_Class) -> UniquePtr<CxxString>;
        fn is_meta(self: &ObjC_Class) -> bool;
        fn super_class(self: &ObjC_Class) -> UniquePtr<ObjC_Class>;
        fn methods(self: &ObjC_Class) -> UniquePtr<ObjC_Class_it_methods>;
        fn protocols(self: &ObjC_Class) -> UniquePtr<ObjC_Class_it_protocols>;
        fn properties(self: &ObjC_Class) -> UniquePtr<ObjC_Class_it_properties>;
        fn ivars(self: &ObjC_Class) -> UniquePtr<ObjC_Class_it_ivars>;
        fn to_decl(self: &ObjC_Class) -> UniquePtr<CxxString>;

        type ObjC_Class_it_ivars;

        fn next(self: Pin<&mut ObjC_Class_it_ivars>) -> UniquePtr<ObjC_IVar>;
        fn size(self: &ObjC_Class_it_ivars) -> u64;

        type ObjC_Class_it_methods;

        fn next(self: Pin<&mut ObjC_Class_it_methods>) -> UniquePtr<ObjC_Method>;
        fn size(self: &ObjC_Class_it_methods) -> u64;

        type ObjC_Class_it_properties;

        fn next(self: Pin<&mut ObjC_Class_it_properties>) -> UniquePtr<ObjC_Property>;
        fn size(self: &ObjC_Class_it_properties) -> u64;

        type ObjC_Class_it_protocols;

        fn next(self: Pin<&mut ObjC_Class_it_protocols>) -> UniquePtr<ObjC_Protocol>;
        fn size(self: &ObjC_Class_it_protocols) -> u64;
    }
    impl UniquePtr<ObjC_Class> {}
    impl UniquePtr<ObjC_Class_it_ivars> {}
    impl UniquePtr<ObjC_Class_it_methods> {}
    impl UniquePtr<ObjC_Class_it_properties> {}
    impl UniquePtr<ObjC_Class_it_protocols> {}
}
