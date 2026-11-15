use lief_ffi as ffi;
use std::collections::HashMap;
use std::marker::PhantomData;

use crate::common::FromFFI;
use crate::elf::note::NoteBase;
use crate::enum_from_int;

enum_from_int! {
    #[allow(non_camel_case_types)]
    /// Auxiliary vector types
    Type: u64 {
        END = 0,
        IGNORE_TY = 1,
        EXECFD = 2,
        PHDR = 3,
        PHENT = 4,
        PHNUM = 5,
        PAGESZ = 6,
        BASE = 7,
        FLAGS = 8,
        ENTRY = 9,
        NOTELF = 10,
        UID = 11,
        EUID = 12,
        GID = 13,
        EGID = 14,
        TGT_PLATFORM = 15,
        HWCAP = 16,
        CLKTCK = 17,
        FPUCW = 18,
        DCACHEBSIZE = 19,
        ICACHEBSIZE = 20,
        UCACHEBSIZE = 21,
        IGNOREPPC = 22,
        SECURE = 23,
        BASE_PLATFORM = 24,
        RANDOM = 25,
        HWCAP2 = 26,
        EXECFN = 31,
        SYSINFO = 32,
        SYSINFO_EHDR = 33,
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
