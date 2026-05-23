#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/ChainedBindingInfo.hpp");

        type MachO_BindingInfo = crate::macho::binding_info::ffi::MachO_BindingInfo;

        type MachO_ChainedBindingInfo;

        #[Self = "MachO_ChainedBindingInfo"]
        fn classof(binding: &MachO_BindingInfo) -> bool;
        fn format(self: &MachO_ChainedBindingInfo) -> u32;
        fn ptr_format(self: &MachO_ChainedBindingInfo) -> u32;
        fn offset(self: &MachO_ChainedBindingInfo) -> u32;
        fn sign_extended_addend(self: &MachO_ChainedBindingInfo) -> u64;
    }

    impl UniquePtr<MachO_ChainedBindingInfo> {}
}
