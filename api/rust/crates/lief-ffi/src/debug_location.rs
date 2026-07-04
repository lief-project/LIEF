#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/debug_location.hpp");

        type DebugLocation;

        fn file(self: &DebugLocation) -> UniquePtr<CxxString>;
        fn line(self: &DebugLocation) -> u64;
    }

    impl UniquePtr<DebugLocation> {}
}
