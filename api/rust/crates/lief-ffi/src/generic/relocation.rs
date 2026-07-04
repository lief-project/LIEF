#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/Abstract/Relocation.hpp");

        type AbstractRelocation;

        fn size(self: &AbstractRelocation) -> u64;
        fn address(self: &AbstractRelocation) -> u64;
    }
}
