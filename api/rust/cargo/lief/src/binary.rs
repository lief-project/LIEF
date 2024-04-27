use lief_ffi as ffi;

use super::elf;
use super::macho;
use super::pe;
use crate::common::FromFFI;
use std::io::{Read, Seek};

#[derive(Debug)]
pub enum Binary {
    ELF(elf::Binary),
    PE(pe::Binary),
    MachO(macho::FatBinary),
}

impl Binary {
    pub fn parse(path: &str) -> Option<Binary> {
        if ffi::ELF_Utils::is_elf(path) {
            return Some(Binary::ELF(elf::Binary::parse(path)));
        }
        if ffi::PE_Utils::is_pe(path) {
            return Some(Binary::PE(pe::Binary::parse(path)));
        }
        if ffi::MachO_Utils::is_macho(path) {
            return Some(Binary::MachO(macho::FatBinary::parse(path)));
        }
        None
    }

    pub fn from<R: Read + Seek>(reader: &mut R) -> Option<Binary> {
        let mut buffer = std::vec::Vec::new();
        if reader.read_to_end(&mut buffer).is_err() {
            return None;
        }

        let mut ffi_stream =
            unsafe { ffi::RustStream::from_rust(buffer.as_mut_ptr(), buffer.len()) };
        buffer.clear();

        if ffi_stream.is_elf() {
            return Some(Binary::ELF(elf::Binary::from_ffi(
                ffi_stream.pin_mut().as_elf(),
            )));
        }
        if ffi_stream.is_macho() {
            return Some(Binary::MachO(macho::FatBinary::from_ffi(
                ffi_stream.pin_mut().as_macho(),
            )));
        }
        if ffi_stream.is_pe() {
            return Some(Binary::PE(pe::Binary::from_ffi(
                ffi_stream.pin_mut().as_pe(),
            )));
        }
        None
    }
}
