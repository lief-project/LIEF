#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ObjC/IVar.hpp");

        type ObjC_IVar;

        fn name(self: &ObjC_IVar) -> UniquePtr<CxxString>;
        fn mangled_type(self: &ObjC_IVar) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<ObjC_IVar> {}
}
