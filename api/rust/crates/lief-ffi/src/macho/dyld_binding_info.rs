#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/DyldBindingInfo.hpp");

        type MachO_BindingInfo = crate::macho::binding_info::ffi::MachO_BindingInfo;

        type MachO_DyldBindingInfo;

        #[Self = "MachO_DyldBindingInfo"]
        fn classof(binding: &MachO_BindingInfo) -> bool;
        fn binding_class(self: &MachO_DyldBindingInfo) -> u64;
        fn binding_type(self: &MachO_DyldBindingInfo) -> u64;
        fn is_non_weak_definition(self: &MachO_DyldBindingInfo) -> bool;
        fn original_offset(self: &MachO_DyldBindingInfo) -> u64;
    }

    impl UniquePtr<MachO_DyldBindingInfo> {}
}
