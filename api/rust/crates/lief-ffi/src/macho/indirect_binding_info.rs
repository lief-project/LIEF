#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/IndirectBindingInfo.hpp");

        type MachO_BindingInfo = crate::macho::binding_info::ffi::MachO_BindingInfo;

        type MachO_IndirectBindingInfo;

        #[Self = "MachO_IndirectBindingInfo"]
        fn classof(binding: &MachO_BindingInfo) -> bool;
    }
    impl UniquePtr<MachO_IndirectBindingInfo> {}
}
