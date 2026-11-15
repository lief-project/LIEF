use lief_ffi as ffi;
use std::marker::PhantomData;
use std::time::Duration;

use crate::common::FromFFI;
use crate::elf::header::Arch;
use crate::elf::note::NoteBase;
use crate::{Error, enum_from_int, to_result};

enum_from_int! {
    #[allow(non_camel_case_types)]
    /// Register for the x86 architecture
    RegX86: u32 {
        EBX = 0,
        ECX = 1,
        EDX = 2,
        ESI = 3,
        EDI = 4,
        EBP = 5,
        EAX = 6,
        DS = 7,
        ES = 8,
        FS = 9,
        GS = 10,
        ORIG_EAX = 11,
        EIP = 12,
        CS = 13,
        EFLAGS = 14,
        ESP = 15,
        SS = 16,
    }
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    /// Register for the x86-64 architecture
    RegX86_64: u32 {
        R15 = 0,
        R14 = 1,
        R13 = 2,
        R12 = 3,
        RBP = 4,
        RBX = 5,
        R11 = 6,
        R10 = 7,
        R9 = 8,
        R8 = 9,
        RAX = 10,
        RCX = 11,
        RDX = 12,
        RSI = 13,
        RDI = 14,
        ORIG_RAX = 15,
        RIP = 16,
        CS = 17,
        EFLAGS = 18,
        RSP = 19,
        SS = 20,
        FS_BASE = 21,
        GS_BASE = 22,
        DS = 23,
        ES = 24,
    }
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    /// Register for the ARM architecture
    RegARM: u32 {
        R0 = 0,
        R1 = 1,
        R2 = 2,
        R3 = 3,
        R4 = 4,
        R5 = 5,
        R6 = 6,
        R7 = 7,
        R8 = 8,
        R9 = 9,
        R10 = 10,
        R11 = 11,
        R12 = 12,
        R13 = 13,
        R14 = 14,
        R15 = 15,
        CPSR = 16,
    }
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    /// Register for the AArch64 architecture
    RegAArch64: u32 {
        X0 = 0,
        X1 = 1,
        X2 = 2,
        X3 = 3,
        X4 = 4,
        X5 = 5,
        X6 = 6,
        X7 = 7,
        X8 = 8,
        X9 = 9,
        X10 = 10,
        X11 = 11,
        X12 = 12,
        X13 = 13,
        X14 = 14,
        X15 = 15,
        X16 = 16,
        X17 = 17,
        X18 = 18,
        X19 = 19,
        X20 = 20,
        X21 = 21,
        X22 = 22,
        X23 = 23,
        X24 = 24,
        X25 = 25,
        X26 = 26,
        X27 = 27,
        X28 = 28,
        X29 = 29,
        X30 = 30,
        X31 = 31,
        PC = 32,
        PSTATE = 33,
    }
}

/// Status information from a core dump
///
/// This structure mirrors the kernel's `prstatus` data embedded in
/// `NT_PRSTATUS` core-dump notes and exposes signal state, process
/// identifiers, and CPU-time accounting.
#[derive(Debug)]
pub struct Status {
    /// Current signal number being delivered
    pub cursig: u16,
    /// Set of pending signals (bitmask)
    pub sigpend: u64,
    /// Set of held (blocked) signals (bitmask)
    pub sighold: u64,
    /// Process ID
    pub pid: i32,
    /// Parent process ID
    pub ppid: i32,
    /// Process group ID
    pub pgrp: i32,
    /// Session ID
    pub sid: i32,
    /// Signal number that caused the core dump
    pub signo: i32,
    /// Signal code providing additional detail
    pub sigcode: i32,
    /// Error number associated with the signal
    pub sigerr: i32,

    /// Reserved field for alignment
    pub reserved: u16,

    /// User CPU time consumed by the process
    pub utime: Duration,
    /// System CPU time consumed by the process
    pub stime: Duration,
    /// User CPU time consumed by waited-for children
    pub cutime: Duration,
    /// System CPU time consumed by waited-for children
    pub cstime: Duration,
}

/// Note representing core process status (`NT_PRSTATUS`)
pub struct PrStatus<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_CorePrStatus>,
    _owner: PhantomData<&'a ffi::ELF_Binary>,
}

impl PrStatus<'_> {
    /// The architecture
    pub fn architecture(&self) -> Arch {
        Arch::from(self.ptr.architecture())
    }

    /// Status information
    pub fn status(&self) -> Status {
        let s = self.ptr.status();
        Status {
            cursig: s.cursig,
            sigpend: s.sigpend,
            sighold: s.sighold,
            pid: s.pid,
            ppid: s.ppid,
            pgrp: s.pgrp,
            sid: s.sid,
            signo: s.signo,
            sigcode: s.code,
            sigerr: s.err,
            reserved: s.reserved,
            utime: Duration::new(s.utime_sec, s.utime_usec as u32),
            stime: Duration::new(s.stime_sec, s.stime_usec as u32),
            cutime: Duration::new(s.cutime_sec, s.cutime_usec as u32),
            cstime: Duration::new(s.cstime_sec, s.cstime_usec as u32),
        }
    }

    /// The program counter
    pub fn pc(&self) -> Result<u64, Error> {
        to_result!(ffi::ELF_CorePrStatus::pc, &self);
    }

    //// The stack pointer value
    pub fn sp(&self) -> Result<u64, Error> {
        to_result!(ffi::ELF_CorePrStatus::sp, &self);
    }

    /// The return value register
    pub fn return_value(&self) -> Result<u64, Error> {
        to_result!(ffi::ELF_CorePrStatus::return_value, &self);
    }

    /// Get all register values
    pub fn register_values(&self) -> Vec<u64> {
        Vec::from(self.ptr.register_values().as_slice())
    }
}

impl NoteBase for PrStatus<'_> {
    fn get_base(&self) -> &ffi::ELF_Note {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl FromFFI<ffi::ELF_CorePrStatus> for PrStatus<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_CorePrStatus>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for PrStatus<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn NoteBase;
        f.debug_struct("CorePrStatus")
            .field("base", &base)
            //.field("architecture", &self.architecture())
            //.field("status", &self.status())
            .finish()
    }
}
