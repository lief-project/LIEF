#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/RsaInfo.hpp");

        type PE_RsaInfo;

        fn key_size(self: &PE_RsaInfo) -> u32;
        fn has_public_key(self: &PE_RsaInfo) -> bool;
        fn has_private_key(self: &PE_RsaInfo) -> bool;
        fn N(self: &PE_RsaInfo) -> UniquePtr<CxxVector<u8>>;
        fn E(self: &PE_RsaInfo) -> UniquePtr<CxxVector<u8>>;
        fn D(self: &PE_RsaInfo) -> UniquePtr<CxxVector<u8>>;
        fn P(self: &PE_RsaInfo) -> UniquePtr<CxxVector<u8>>;
        fn Q(self: &PE_RsaInfo) -> UniquePtr<CxxVector<u8>>;
    }

    impl UniquePtr<PE_RsaInfo> {}
}
