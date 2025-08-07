use lief_ffi as ffi;

use super::elf;
use super::macho;
use super::pe;
use super::coff;
use crate::common::FromFFI;
use std::path::Path;
use std::io::{Read, Seek};

#[derive(Debug)]
/// Enum that wraps all the executable formats supported by LIEF
pub enum Binary {
    /// An ELF binary
    ELF(elf::Binary),

    /// A PE binary
    PE(pe::Binary),

    /// A Mach-O (FAT) binary
    MachO(macho::FatBinary),

    /// A COFF binary object
    COFF(coff::Binary)
}

impl Binary {
    /// Parse form a file path
    ///
    /// ```
    /// if let Some(Binary::ELF(elf)) = Binary::parse("/bin/ls") {
    ///     // ...
    /// }
    /// ```
    pub fn parse<P: AsRef<Path>>(path: P) -> Option<Binary> {
        let path_str = path.as_ref().to_str().unwrap();
        if ffi::ELF_Utils::is_elf(path_str) {
            if let Some(elf) = elf::Binary::parse(path) {
                return Some(Binary::ELF(elf));
            }
            return None;
        }
        if ffi::PE_Utils::is_pe(path_str) {
            if let Some(pe) = pe::Binary::parse(path) {
                return Some(Binary::PE(pe));
            }
            return None;
        }
        if ffi::MachO_Utils::is_macho(path_str) {
            if let Some(fat) = macho::FatBinary::parse(path) {
                return Some(Binary::MachO(fat));
            }
            return None;
        }

        if ffi::COFF_Utils::is_coff(path_str) {
            if let Some(coff) = coff::Binary::parse(path) {
                return Some(Binary::COFF(coff));
            }
            return None;
        }
        None
    }
    /// Parse from an input that implements `Read + Seek` traits
    ///
    /// ```
    /// let mut file = std::fs::File::open("C:/test.ext").expect("Can't open the file");
    /// if let Some(Binary::PE(pe)) = Binary::from(&mut file) {
    ///     // ...
    /// }
    /// ```
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

        if ffi_stream.is_coff() {
            return Some(Binary::COFF(coff::Binary::from_ffi(
                ffi_stream.pin_mut().as_coff(),
            )));
        }
        None
    }
}
