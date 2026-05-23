#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/Abstract/Function.hpp");

        type AbstractFunction;

        fn address(self: &AbstractFunction) -> u64;
        fn flags(self: &AbstractFunction) -> u32;
    }

    impl UniquePtr<AbstractFunction> {}
}
