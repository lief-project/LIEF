#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ObjC/Protocol.hpp");

        type ObjC_DeclOpt = crate::objc::decl_opt::ffi::ObjC_DeclOpt;
        type ObjC_Method = crate::objc::method::ffi::ObjC_Method;
        type ObjC_Property = crate::objc::property::ffi::ObjC_Property;

        type ObjC_Protocol;

        fn mangled_name(self: &ObjC_Protocol) -> UniquePtr<CxxString>;
        fn optional_methods(self: &ObjC_Protocol) -> UniquePtr<ObjC_Protocol_it_opt_methods>;
        fn required_methods(self: &ObjC_Protocol) -> UniquePtr<ObjC_Protocol_it_req_methods>;
        fn properties(self: &ObjC_Protocol) -> UniquePtr<ObjC_Protocol_it_properties>;
        fn to_decl(self: &ObjC_Protocol) -> UniquePtr<CxxString>;
        fn to_decl_with_opt(self: &ObjC_Protocol, opt: &ObjC_DeclOpt) -> UniquePtr<CxxString>;

        type ObjC_Protocol_it_opt_methods;

        fn next(self: Pin<&mut ObjC_Protocol_it_opt_methods>) -> UniquePtr<ObjC_Method>;
        fn size(self: &ObjC_Protocol_it_opt_methods) -> u64;

        type ObjC_Protocol_it_properties;

        fn next(self: Pin<&mut ObjC_Protocol_it_properties>) -> UniquePtr<ObjC_Property>;
        fn size(self: &ObjC_Protocol_it_properties) -> u64;

        type ObjC_Protocol_it_req_methods;

        fn next(self: Pin<&mut ObjC_Protocol_it_req_methods>) -> UniquePtr<ObjC_Method>;
        fn size(self: &ObjC_Protocol_it_req_methods) -> u64;
    }

    impl UniquePtr<ObjC_Protocol> {}
    impl UniquePtr<ObjC_Protocol_it_opt_methods> {}
    impl UniquePtr<ObjC_Protocol_it_properties> {}
    impl UniquePtr<ObjC_Protocol_it_req_methods> {}
}
