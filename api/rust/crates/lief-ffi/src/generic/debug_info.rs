#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/Abstract/DebugInfo.hpp");

        type AbstracDebugInfo;

        fn find_function_address(
            self: &AbstracDebugInfo,
            name: &CxxString,
            is_set: Pin<&mut u32>,
        ) -> u64;
    }

    impl UniquePtr<AbstracDebugInfo> {}
}
