#[repr(C)]
pub struct DeclOpt {
    pub show_annotations: bool,
}

unsafe impl cxx::ExternType for DeclOpt {
    type Id = cxx::type_id!("ObjC_DeclOpt");
    type Kind = cxx::kind::Trivial;
}

#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ObjC/DeclOpt.hpp");

        type ObjC_DeclOpt = crate::objc::decl_opt::DeclOpt;
    }
}
