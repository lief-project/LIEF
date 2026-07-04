#[repr(C)]
pub struct extract_opt {
    pub pack: bool,
    pub fix_branches: bool,
    pub fix_memory: bool,
    pub fix_relocations: bool,
    pub fix_objc: bool,
    pub create_dyld_chained_fixup_cmd: bool,
    pub create_dyld_chained_fixup_cmd_set: bool,
}

unsafe impl cxx::ExternType for extract_opt {
    type Id = cxx::type_id!("dsc_Dylib_extract_opt");
    type Kind = cxx::kind::Trivial;
}

#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DyldSharedCache/Dylib.hpp");

        type MachO_Binary = crate::macho::binary::ffi::MachO_Binary;

        type dsc_Dylib_extract_opt = crate::dsc::dylib::extract_opt;

        type dsc_Dylib;

        fn path(self: &dsc_Dylib) -> UniquePtr<CxxString>;
        fn address(self: &dsc_Dylib) -> u64;
        fn modtime(self: &dsc_Dylib) -> u64;
        fn inode(self: &dsc_Dylib) -> u64;
        fn padding(self: &dsc_Dylib) -> u64;
        fn get_macho(self: &dsc_Dylib, opt: &dsc_Dylib_extract_opt) -> UniquePtr<MachO_Binary>;
    }

    impl UniquePtr<dsc_Dylib> {}
    impl UniquePtr<dsc_Dylib_extract_opt> {}
}
