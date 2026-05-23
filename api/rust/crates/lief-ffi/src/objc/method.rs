#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ObjC/Method.hpp");

        type ObjC_Method;

        fn name(self: &ObjC_Method) -> UniquePtr<CxxString>;
        fn mangled_type(self: &ObjC_Method) -> UniquePtr<CxxString>;
        fn address(self: &ObjC_Method) -> u64;
        fn is_instance(self: &ObjC_Method) -> bool;
    }

    impl UniquePtr<ObjC_Method> {}
}
