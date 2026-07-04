#[repr(C)]
pub struct Status {
    pub signo: i32,
    pub code: i32,
    pub err: i32,

    pub cursig: u16,
    pub reserved: u16,

    pub sigpend: u64,
    pub sighold: u64,

    pub pid: i32,
    pub ppid: i32,
    pub pgrp: i32,
    pub sid: i32,

    pub utime_sec: u64,
    pub utime_usec: u64,

    pub stime_sec: u64,
    pub stime_usec: u64,

    pub cutime_sec: u64,
    pub cutime_usec: u64,

    pub cstime_sec: u64,
    pub cstime_usec: u64,
}

unsafe impl cxx::ExternType for Status {
    type Id = cxx::type_id!("ELF_CorePrStatus_Status");
    type Kind = cxx::kind::Trivial;
}

#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/CorePrStatus.hpp");

        type Span = crate::utils::ffi::Span;
        type ELF_Note = crate::elf::note::ffi::ELF_Note;
        type ELF_CorePrStatus_Status = crate::elf::core_pr_status::Status;

        type ELF_CorePrStatus;

        #[Self = "ELF_CorePrStatus"]
        fn classof(note: &ELF_Note) -> bool;
        fn architecture(self: &ELF_CorePrStatus) -> u32;
        fn pc(self: &ELF_CorePrStatus, err: Pin<&mut u32>) -> u64;
        fn sp(self: &ELF_CorePrStatus, err: Pin<&mut u32>) -> u64;
        fn return_value(self: &ELF_CorePrStatus, err: Pin<&mut u32>) -> u64;
        fn register_values(self: &ELF_CorePrStatus) -> UniquePtr<CxxVector<u64>>;
        fn status(self: &ELF_CorePrStatus) -> ELF_CorePrStatus_Status;

    }
    impl UniquePtr<ELF_CorePrStatus> {}
}
