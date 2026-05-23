#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/Abstract/Symbol.hpp");

        type AbstractSymbol;

        fn name(self: &AbstractSymbol) -> UniquePtr<CxxString>;
        fn size(self: &AbstractSymbol) -> u64;
        fn value(self: &AbstractSymbol) -> u64;
        fn set_name(self: Pin<&mut AbstractSymbol>, name: &CxxString);
        fn set_size(self: Pin<&mut AbstractSymbol>, sz: u64);
        fn set_value(self: Pin<&mut AbstractSymbol>, value: u64);
    }
}
