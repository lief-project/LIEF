#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime/Module.hpp");

        type runtime_Module;
        type runtime_it_modules;

        fn name(self: &runtime_Module) -> UniquePtr<CxxString>;
        fn path(self: &runtime_Module) -> UniquePtr<CxxString>;
        fn imagebase(self: &runtime_Module) -> u64;
        fn size(self: &runtime_Module) -> u64;
        fn end(self: &runtime_Module) -> u64;
        fn contains(self: &runtime_Module, addr: u64) -> bool;

        fn next(self: Pin<&mut runtime_it_modules>) -> UniquePtr<runtime_Module>;

        fn runtime_modules() -> UniquePtr<runtime_it_modules>;
        fn runtime_module_from_name(name: &CxxString) -> UniquePtr<runtime_Module>;
        fn runtime_module_from_path(path: &CxxString) -> UniquePtr<runtime_Module>;
        fn runtime_module_from_addr(addr: u64) -> UniquePtr<runtime_Module>;
        fn runtime_current_module() -> UniquePtr<runtime_Module>;
    }
    impl UniquePtr<runtime_Module> {}
    impl UniquePtr<runtime_it_modules> {}
}
