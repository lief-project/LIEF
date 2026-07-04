#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/FatBinary.hpp");

        type MachO_Binary = crate::macho::binary::ffi::MachO_Binary;

        type MachO_FatBinary;

        #[Self = "MachO_FatBinary"]
        fn parse(path: &CxxString) -> UniquePtr<MachO_FatBinary>;
        #[Self = "MachO_FatBinary"]
        fn parse_with_config(
            path: &CxxString,
            config: &MachO_ParserConfig,
        ) -> UniquePtr<MachO_FatBinary>;
        fn size(self: &MachO_FatBinary) -> u32;
        fn write(self: Pin<&mut MachO_FatBinary>, output: &CxxString);
        fn binary_at(self: &MachO_FatBinary, index: u32) -> UniquePtr<MachO_Binary>;
        fn binary_from_arch(self: &MachO_FatBinary, cpu: i32) -> UniquePtr<MachO_Binary>;

        type MachO_ParserConfig;

        #[Self = "MachO_ParserConfig"]
        fn create() -> UniquePtr<MachO_ParserConfig>;
        fn set_parse_overlay(self: Pin<&mut MachO_ParserConfig>, value: bool);
        fn set_parse_dyld_exports(self: Pin<&mut MachO_ParserConfig>, value: bool);
        fn set_parse_dyld_bindings(self: Pin<&mut MachO_ParserConfig>, value: bool);
        fn set_parse_dyld_rebases(self: Pin<&mut MachO_ParserConfig>, value: bool);
        fn set_fix_from_memory(self: Pin<&mut MachO_ParserConfig>, value: bool);
        fn set_from_dyld_shared_cache(self: Pin<&mut MachO_ParserConfig>, value: bool);
    }
    impl UniquePtr<MachO_FatBinary> {}
    impl UniquePtr<MachO_ParserConfig> {}
}
