use super::binary::Binary;
use lief_ffi as ffi;

use crate::common::FromFFI;

pub struct FatBinary {
    pub nb_macho: u32,
    ptr: cxx::UniquePtr<ffi::MachO_FatBinary>,
}

impl FromFFI<ffi::MachO_FatBinary> for FatBinary {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::MachO_FatBinary>) -> Self {
        Self {
            nb_macho: ptr.size(),
            ptr,
        }
    }
}

impl std::fmt::Debug for FatBinary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FatBinary")
            .field("nb_macho", &self.nb_macho)
            .finish()
    }
}

pub struct FatBinaryIterator<'a> {
    index: u32,
    fat: &'a FatBinary,
}

impl FatBinary {
    pub fn parse(path: &str) -> FatBinary {
        let bin = ffi::MachO_FatBinary::parse(path);
        FatBinary {
            nb_macho: bin.size(),
            ptr: bin,
        }
    }

    pub fn iter(&self) -> FatBinaryIterator {
        FatBinaryIterator {
            index: 0,
            fat: self,
        }
    }
}

impl<'a> Iterator for FatBinaryIterator<'a> {
    type Item = Binary;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.fat.nb_macho {
            return None;
        }
        self.index += 1;
        Some(Binary::from_ffi(self.fat.ptr.binary_at(self.index - 1)))
    }
}
