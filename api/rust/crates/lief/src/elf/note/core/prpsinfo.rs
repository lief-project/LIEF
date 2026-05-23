use lief_ffi as ffi;
use std::marker::PhantomData;

use crate::common::FromFFI;
use crate::elf::note::NoteBase;

/// Process info from a core dump
#[derive(Debug)]
pub struct Info {
    /// Numeric process state
    pub state: u32,
    /// Printable character representing state
    pub sname: String,
    /// Whether the process is a zombie
    pub zombie: bool,
    /// Nice value
    pub nice: u32,
    /// Process flag
    pub flag: u64,
    /// Process user ID
    pub uid: u32,
    /// Process group ID
    pub gid: u32,
    /// Process ID
    pub pid: u32,
    /// Process parent ID
    pub ppid: u32,
    /// Process group
    pub pgrp: u32,
    /// Process session id
    pub sid: u32,
    /// Filename of the executable
    pub filename: String,
    /// Initial part of the arguments
    pub args: String,
}

/// Note representing core process info (`NT_PRPSINFO`)
pub struct PrPsInfo<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_CorePrPsInfo>,
    _owner: PhantomData<&'a ffi::ELF_Binary>,
}

impl PrPsInfo<'_> {
    pub fn info(&self) -> Option<Info> {
        todo!();
    }
}

impl NoteBase for PrPsInfo<'_> {
    fn get_base(&self) -> &ffi::ELF_Note {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl FromFFI<ffi::ELF_CorePrPsInfo> for PrPsInfo<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_CorePrPsInfo>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for PrPsInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn NoteBase;
        f.debug_struct("CorePrPsInfo").field("base", &base).finish()
    }
}
