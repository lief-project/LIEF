#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/Stub.hpp");

        type Span = crate::utils::ffi::Span;
        type MachO_Stub;

        fn raw(self: &MachO_Stub) -> Span;
        fn address(self: &MachO_Stub) -> u64;
        fn target(self: &MachO_Stub, err: Pin<&mut u32>) -> u64;
    }

    impl UniquePtr<MachO_Stub> {}
}
