#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/LazyLoadDylibInfo.hpp");

        type Span = crate::utils::ffi::Span;
        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_LazyLoadDylibInfo;

        #[Self = "MachO_LazyLoadDylibInfo"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn data_offset(self: &MachO_LazyLoadDylibInfo) -> u32;
        fn data_size(self: &MachO_LazyLoadDylibInfo) -> u32;
        fn content(self: &MachO_LazyLoadDylibInfo) -> Span;
        fn load_path(self: &MachO_LazyLoadDylibInfo) -> UniquePtr<CxxString>;
        fn flag_image_offset(self: &MachO_LazyLoadDylibInfo) -> u32;
        fn flags(self: &MachO_LazyLoadDylibInfo) -> u16;
        fn may_be_missing(self: &MachO_LazyLoadDylibInfo) -> bool;
        fn pointer_format(self: &MachO_LazyLoadDylibInfo) -> u16;
        fn chain_start_image_offset(self: &MachO_LazyLoadDylibInfo) -> u32;
        fn symbols(self: &MachO_LazyLoadDylibInfo) -> UniquePtr<CxxVector<CxxString>>;
        fn fixups(self: &MachO_LazyLoadDylibInfo) -> UniquePtr<MachO_LazyLoadDylibInfo_it_fixups>;

        fn set_load_path(self: Pin<&mut MachO_LazyLoadDylibInfo>, value: &CxxString);
        fn set_flag_image_offset(self: Pin<&mut MachO_LazyLoadDylibInfo>, value: u32);
        fn set_flags(self: Pin<&mut MachO_LazyLoadDylibInfo>, value: u16);
        fn set_may_be_missing(self: Pin<&mut MachO_LazyLoadDylibInfo>, value: bool);
        fn set_pointer_format(self: Pin<&mut MachO_LazyLoadDylibInfo>, value: u16);
        fn set_chain_start_image_offset(self: Pin<&mut MachO_LazyLoadDylibInfo>, value: u32);
        fn add_symbol(self: Pin<&mut MachO_LazyLoadDylibInfo>, value: &CxxString);
        fn clear_symbols(self: Pin<&mut MachO_LazyLoadDylibInfo>);

        type MachO_LazyLoadDylibInfo_Fixup;

        fn address(self: &MachO_LazyLoadDylibInfo_Fixup) -> u64;
        fn ordinal(self: &MachO_LazyLoadDylibInfo_Fixup) -> u32;
        fn symbol(self: &MachO_LazyLoadDylibInfo_Fixup) -> UniquePtr<CxxString>;
        fn is_auth(self: &MachO_LazyLoadDylibInfo_Fixup) -> bool;
        fn to_string(self: &MachO_LazyLoadDylibInfo_Fixup) -> UniquePtr<CxxString>;

        type MachO_LazyLoadDylibInfo_it_fixups;

        fn next(
            self: Pin<&mut MachO_LazyLoadDylibInfo_it_fixups>,
        ) -> UniquePtr<MachO_LazyLoadDylibInfo_Fixup>;
        fn size(self: &MachO_LazyLoadDylibInfo_it_fixups) -> u64;
    }

    impl UniquePtr<MachO_LazyLoadDylibInfo> {}
    impl UniquePtr<MachO_LazyLoadDylibInfo_Fixup> {}
    impl UniquePtr<MachO_LazyLoadDylibInfo_it_fixups> {}
}
