use lief_ffi as ffi;
use std::collections::HashMap;
use std::marker::PhantomData;

use crate::common::FromFFI;
use crate::elf::note::NoteBase;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Auxiliary vector types
pub enum Type {
    END,
    IGNORE_TY,
    EXECFD,
    PHDR,
    PHENT,
    PHNUM,
    PAGESZ,
    BASE,
    FLAGS,
    ENTRY,
    NOTELF,
    UID,
    EUID,
    GID,
    EGID,
    TGT_PLATFORM,
    HWCAP,
    CLKTCK,
    FPUCW,
    DCACHEBSIZE,
    ICACHEBSIZE,
    UCACHEBSIZE,
    IGNOREPPC,
    SECURE,
    BASE_PLATFORM,
    RANDOM,
    HWCAP2,
    EXECFN,
    SYSINFO,
    SYSINFO_EHDR,
    UNKNOWN(u64),
}

impl From<u64> for Type {
    fn from(value: u64) -> Self {
        match value {
            0 => Type::END,
            1 => Type::IGNORE_TY,
            2 => Type::EXECFD,
            3 => Type::PHDR,
            4 => Type::PHENT,
            5 => Type::PHNUM,
            6 => Type::PAGESZ,
            7 => Type::BASE,
            8 => Type::FLAGS,
            9 => Type::ENTRY,
            10 => Type::NOTELF,
            11 => Type::UID,
            12 => Type::EUID,
            13 => Type::GID,
            14 => Type::EGID,
            15 => Type::TGT_PLATFORM,
            16 => Type::HWCAP,
            17 => Type::CLKTCK,
            18 => Type::FPUCW,
            19 => Type::DCACHEBSIZE,
            20 => Type::ICACHEBSIZE,
            21 => Type::UCACHEBSIZE,
            22 => Type::IGNOREPPC,
            23 => Type::SECURE,
            24 => Type::BASE_PLATFORM,
            25 => Type::RANDOM,
            26 => Type::HWCAP2,
            31 => Type::EXECFN,
            32 => Type::SYSINFO,
            33 => Type::SYSINFO_EHDR,
            _ => Type::UNKNOWN(value),
        }
    }
}

/// Note representing core auxiliary vector (`NT_AUXV`)
pub struct Auxv<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_CoreAuxv>,
    _owner: PhantomData<&'a ffi::ELF_Binary>,
}

impl Auxv<'_> {
    /// Return the auxiliary values as a map of (Type, value)
    pub fn values(&self) -> HashMap<Type, u64> {
        self.ptr
            .values()
            .as_slice()
            .chunks_exact(2)
            .map(|c| (Type::from(c[0]), c[1]))
            .collect()
    }
}

impl NoteBase for Auxv<'_> {
    fn get_base(&self) -> &ffi::ELF_Note {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl FromFFI<ffi::ELF_CoreAuxv> for Auxv<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_CoreAuxv>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for Auxv<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn NoteBase;
        f.debug_struct("CoreAuxv").field("base", &base).finish()
    }
}
