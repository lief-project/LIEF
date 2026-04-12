use lief_ffi as ffi;
use std::marker::PhantomData;
use std::time::Duration;

use crate::common::FromFFI;
use crate::elf::header::Arch;
use crate::elf::note::NoteBase;
use crate::{to_result, Error};

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Register for the x86 architecture
pub enum RegX86 {
    EBX,
    ECX,
    EDX,
    ESI,
    EDI,
    EBP,
    EAX,
    DS,
    ES,
    FS,
    GS,
    ORIG_EAX,
    EIP,
    CS,
    EFLAGS,
    ESP,
    SS,
    UNKNOWN(u32),
}

impl From<u32> for RegX86 {
    fn from(value: u32) -> Self {
        match value {
            0 => RegX86::EBX,
            1 => RegX86::ECX,
            2 => RegX86::EDX,
            3 => RegX86::ESI,
            4 => RegX86::EDI,
            5 => RegX86::EBP,
            6 => RegX86::EAX,
            7 => RegX86::DS,
            8 => RegX86::ES,
            9 => RegX86::FS,
            10 => RegX86::GS,
            11 => RegX86::ORIG_EAX,
            12 => RegX86::EIP,
            13 => RegX86::CS,
            14 => RegX86::EFLAGS,
            15 => RegX86::ESP,
            16 => RegX86::SS,
            _ => RegX86::UNKNOWN(value),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Register for the x86-64 architecture
pub enum RegX86_64 {
    R15,
    R14,
    R13,
    R12,
    RBP,
    RBX,
    R11,
    R10,
    R9,
    R8,
    RAX,
    RCX,
    RDX,
    RSI,
    RDI,
    ORIG_RAX,
    RIP,
    CS,
    EFLAGS,
    RSP,
    SS,
    FS_BASE,
    GS_BASE,
    DS,
    ES,
    UNKNOWN(u32),
}

impl From<u32> for RegX86_64 {
    fn from(value: u32) -> Self {
        match value {
            0 => RegX86_64::R15,
            1 => RegX86_64::R14,
            2 => RegX86_64::R13,
            3 => RegX86_64::R12,
            4 => RegX86_64::RBP,
            5 => RegX86_64::RBX,
            6 => RegX86_64::R11,
            7 => RegX86_64::R10,
            8 => RegX86_64::R9,
            9 => RegX86_64::R8,
            10 => RegX86_64::RAX,
            11 => RegX86_64::RCX,
            12 => RegX86_64::RDX,
            13 => RegX86_64::RSI,
            14 => RegX86_64::RDI,
            15 => RegX86_64::ORIG_RAX,
            16 => RegX86_64::RIP,
            17 => RegX86_64::CS,
            18 => RegX86_64::EFLAGS,
            19 => RegX86_64::RSP,
            20 => RegX86_64::SS,
            21 => RegX86_64::FS_BASE,
            22 => RegX86_64::GS_BASE,
            23 => RegX86_64::DS,
            24 => RegX86_64::ES,
            _ => RegX86_64::UNKNOWN(value),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Register for the ARM architecture
pub enum RegARM {
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    CPSR,
    UNKNOWN(u32),
}

impl From<u32> for RegARM {
    fn from(value: u32) -> Self {
        match value {
            0 => RegARM::R0,
            1 => RegARM::R1,
            2 => RegARM::R2,
            3 => RegARM::R3,
            4 => RegARM::R4,
            5 => RegARM::R5,
            6 => RegARM::R6,
            7 => RegARM::R7,
            8 => RegARM::R8,
            9 => RegARM::R9,
            10 => RegARM::R10,
            11 => RegARM::R11,
            12 => RegARM::R12,
            13 => RegARM::R13,
            14 => RegARM::R14,
            15 => RegARM::R15,
            16 => RegARM::CPSR,
            _ => RegARM::UNKNOWN(value),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Register for the AArch64 architecture
pub enum RegAArch64 {
    X0,
    X1,
    X2,
    X3,
    X4,
    X5,
    X6,
    X7,
    X8,
    X9,
    X10,
    X11,
    X12,
    X13,
    X14,
    X15,
    X16,
    X17,
    X18,
    X19,
    X20,
    X21,
    X22,
    X23,
    X24,
    X25,
    X26,
    X27,
    X28,
    X29,
    X30,
    X31,
    PC,
    PSTATE,
    UNKNOWN(u32),
}

impl From<u32> for RegAArch64 {
    fn from(value: u32) -> Self {
        match value {
            0 => RegAArch64::X0,
            1 => RegAArch64::X1,
            2 => RegAArch64::X2,
            3 => RegAArch64::X3,
            4 => RegAArch64::X4,
            5 => RegAArch64::X5,
            6 => RegAArch64::X6,
            7 => RegAArch64::X7,
            8 => RegAArch64::X8,
            9 => RegAArch64::X9,
            10 => RegAArch64::X10,
            11 => RegAArch64::X11,
            12 => RegAArch64::X12,
            13 => RegAArch64::X13,
            14 => RegAArch64::X14,
            15 => RegAArch64::X15,
            16 => RegAArch64::X16,
            17 => RegAArch64::X17,
            18 => RegAArch64::X18,
            19 => RegAArch64::X19,
            20 => RegAArch64::X20,
            21 => RegAArch64::X21,
            22 => RegAArch64::X22,
            23 => RegAArch64::X23,
            24 => RegAArch64::X24,
            25 => RegAArch64::X25,
            26 => RegAArch64::X26,
            27 => RegAArch64::X27,
            28 => RegAArch64::X28,
            29 => RegAArch64::X29,
            30 => RegAArch64::X30,
            31 => RegAArch64::X31,
            32 => RegAArch64::PC,
            33 => RegAArch64::PSTATE,
            _ => RegAArch64::UNKNOWN(value),
        }
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
        let status_ffi = self.ptr.status();
        Status {
            cursig: status_ffi.cursig,
            sigpend: status_ffi.sigpend,
            sighold: status_ffi.sighold,
            pid: status_ffi.pid,
            ppid: status_ffi.ppid,
            pgrp: status_ffi.pgrp,
            sid: status_ffi.sid,
            signo: status_ffi.signo,
            sigcode: status_ffi.code,
            sigerr: status_ffi.err,
            reserved: status_ffi.reserved,
            utime: Duration::new(status_ffi.utime_sec, status_ffi.utime_usec as u32),
            stime: Duration::new(status_ffi.stime_sec, status_ffi.stime_usec as u32),
            cutime: Duration::new(status_ffi.cutime_sec, status_ffi.cutime_usec as u32),
            cstime: Duration::new(status_ffi.cstime_sec, status_ffi.cstime_usec as u32),
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
