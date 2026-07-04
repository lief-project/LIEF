#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/debug/PDBChecksum.hpp");

        type Span = crate::utils::ffi::Span;
        type PE_Debug = crate::pe::debug::debug::ffi::PE_Debug;

        type PE_PDBChecksum;

        fn hash(self: &PE_PDBChecksum) -> Span;
        #[Self = "PE_PDBChecksum"]
        fn classof(entry: &PE_Debug) -> bool;
        fn algo(self: &PE_PDBChecksum) -> u32;
    }
    impl UniquePtr<PE_PDBChecksum> {}
}
