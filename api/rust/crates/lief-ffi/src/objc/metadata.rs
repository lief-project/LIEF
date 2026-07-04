#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ObjC/Metadata.hpp");

        type ObjC_Class = crate::objc::class::ffi::ObjC_Class;
        type ObjC_DeclOpt = crate::objc::decl_opt::ffi::ObjC_DeclOpt;
        type ObjC_Protocol = crate::objc::protocol::ffi::ObjC_Protocol;

        type ObjC_Metadata;

        fn get_class(self: &ObjC_Metadata, name: &CxxString) -> UniquePtr<ObjC_Class>;
        fn get_protocol(self: &ObjC_Metadata, name: &CxxString) -> UniquePtr<ObjC_Protocol>;
        fn classes(self: &ObjC_Metadata) -> UniquePtr<ObjC_Metadata_it_classes>;
        fn protocols(self: &ObjC_Metadata) -> UniquePtr<ObjC_Metadata_it_protocols>;
        fn to_decl(self: &ObjC_Metadata) -> UniquePtr<CxxString>;
        fn to_decl_with_opt(self: &ObjC_Metadata, opt: &ObjC_DeclOpt) -> UniquePtr<CxxString>;

        type ObjC_Metadata_it_classes;

        fn next(self: Pin<&mut ObjC_Metadata_it_classes>) -> UniquePtr<ObjC_Class>;
        fn size(self: &ObjC_Metadata_it_classes) -> u64;

        type ObjC_Metadata_it_protocols;

        fn next(self: Pin<&mut ObjC_Metadata_it_protocols>) -> UniquePtr<ObjC_Protocol>;
        fn size(self: &ObjC_Metadata_it_protocols) -> u64;
    }

    impl UniquePtr<ObjC_Metadata> {}
    impl UniquePtr<ObjC_Metadata_it_classes> {}
    impl UniquePtr<ObjC_Metadata_it_protocols> {}
}
