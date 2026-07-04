#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/debug/FPO.hpp");

        type PE_Debug = crate::pe::debug::debug::ffi::PE_Debug;

        type PE_FPO;

        #[Self = "PE_FPO"]
        fn classof(entry: &PE_Debug) -> bool;
        fn entries(self: &PE_FPO) -> UniquePtr<PE_FPO_it_entries>;

        type PE_FPO_entry_t;

        fn rva(self: &PE_FPO_entry_t) -> u32;
        fn reserved(self: &PE_FPO_entry_t) -> u16;
        fn get_type(self: &PE_FPO_entry_t) -> u32;
        fn to_string(self: &PE_FPO_entry_t) -> UniquePtr<CxxString>;
        fn proc_size(self: &PE_FPO_entry_t) -> u32;
        fn nb_locals(self: &PE_FPO_entry_t) -> u32;
        fn parameters_size(self: &PE_FPO_entry_t) -> u32;
        fn prolog_size(self: &PE_FPO_entry_t) -> u16;
        fn nb_saved_regs(self: &PE_FPO_entry_t) -> u16;
        fn use_seh(self: &PE_FPO_entry_t) -> bool;
        fn use_bp(self: &PE_FPO_entry_t) -> bool;

        type PE_FPO_it_entries;

        fn next(self: Pin<&mut PE_FPO_it_entries>) -> UniquePtr<PE_FPO_entry_t>;
        fn size(self: &PE_FPO_it_entries) -> u64;
    }
    impl UniquePtr<PE_FPO> {}
    impl UniquePtr<PE_FPO_entry_t> {}
    impl UniquePtr<PE_FPO_it_entries> {}
}
