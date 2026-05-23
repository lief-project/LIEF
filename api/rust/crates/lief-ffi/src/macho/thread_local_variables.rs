#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/ThreadLocalVariables.hpp");
        include!("LIEF/rust/MachO/Relocation.hpp");

        type MachO_Section = crate::macho::section::ffi::MachO_Section;

        type MachO_ThreadLocalVariables;

        #[Self = "MachO_ThreadLocalVariables"]
        fn classof(sec: &MachO_Section) -> bool;
        fn nb_thunks(self: &MachO_ThreadLocalVariables) -> usize;
        fn thunks(
            self: &MachO_ThreadLocalVariables,
        ) -> UniquePtr<MachO_ThreadLocalVariables_it_thunks>;
        fn get_thunk(
            self: &MachO_ThreadLocalVariables,
            idx: u64,
        ) -> UniquePtr<MachO_ThreadLocalVariables_Thunk>;
        fn set_thunk(
            self: Pin<&mut MachO_ThreadLocalVariables>,
            idx: u64,
            func: u64,
            key: u64,
            offset: u64,
        );

        type MachO_ThreadLocalVariables_Thunk;

        fn key(self: &MachO_ThreadLocalVariables_Thunk) -> u64;
        fn offset(self: &MachO_ThreadLocalVariables_Thunk) -> u64;
        fn func(self: &MachO_ThreadLocalVariables_Thunk) -> u64;

        type MachO_ThreadLocalVariables_it_thunks;

        fn next(
            self: Pin<&mut MachO_ThreadLocalVariables_it_thunks>,
        ) -> UniquePtr<MachO_ThreadLocalVariables_Thunk>;
        fn size(self: &MachO_ThreadLocalVariables_it_thunks) -> u64;
    }
    impl UniquePtr<MachO_ThreadLocalVariables> {}
    impl UniquePtr<MachO_ThreadLocalVariables_it_thunks> {}
    impl UniquePtr<MachO_ThreadLocalVariables_Thunk> {}
}
