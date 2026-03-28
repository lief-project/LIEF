//! Module for the Mach-O file format support in LIEF.
//!
//! To get started, one can use [`crate::macho::parse`], [`crate::macho::FatBinary::parse`] or
//! [`crate::Binary::parse`] to instantiate a [`crate::macho::FatBinary`].
//!
//! Even though the targeted Mach-O binary is not FAT, LIEF **always** return a [`crate::macho::FatBinary`]
//! which can wrap a single [`Binary`].
//!
//! ```
//! let fat = lief::macho::parse("non-fat.macho").unwrap();
//! assert!(fat.iter().len() == 1);
//!
//! let fat = lief::macho::parse("real-fat.macho").unwrap();
//! assert!(fat.iter().len() > 1);
//! ```
//!
//! The [`Binary`] structure exposes the main interface to inspect or modify Mach-O binaries:
//!
//! ```
//! fn inspect_macho(macho: &lief::macho::Binary) {
//!     for cmd in macho.commands() {
//!         println!("{:?}", cmd);
//!     }
//! }
//! ```
//!
pub mod binary;
pub mod binding_info;
pub mod commands;
pub mod export_info;
pub mod fat_binary;
pub mod parser_config;
pub mod relocation;
pub mod section;
pub mod symbol;
pub mod header;
pub mod stub;
pub mod builder;

use std::path::Path;
use lief_ffi as ffi;

#[doc(inline)]
pub use binary::Binary;
#[doc(inline)]
pub use binding_info::BindingInfo;
#[doc(inline)]
pub use export_info::ExportInfo;
#[doc(inline)]
pub use fat_binary::FatBinary;
#[doc(inline)]
pub use relocation::Relocation;
#[doc(inline)]
pub use section::Section;
#[doc(inline)]
pub use symbol::Symbol;
#[doc(inline)]
pub use commands::Commands;
#[doc(inline)]
pub use header::Header;
#[doc(inline)]
pub use stub::Stub;

use crate::common::AsFFI;

#[doc(inline)]
pub use parser_config::Config as ParserConfig;

/// Parse a Mach-O file from the given file path
pub fn parse<P: AsRef<Path>>(path: P) -> Option<FatBinary> {
    FatBinary::parse(path)
}

/// Parse a Mach-O file from the given file path with the provided parser
/// configuration
pub fn parse_with_config<P: AsRef<Path>>(path: P, config: &ParserConfig) -> Option<FatBinary> {
    FatBinary::parse_with_config(path, config)
}

/// Check that the layout of the given binary is correct from the loader
/// perspective
pub fn check_layout(binary: &Binary) -> Result<(), String> {
    cxx::let_cxx_string!(error = "");
    unsafe {
        if ffi::MachO_Utils::check_layout(binary.as_ffi(), error.as_mut().get_unchecked_mut()) {
            return Ok(());
        }
    }
    Err(error.to_string())
}

/// Check that the layout of the given FAT binary is correct from the loader
/// perspective
pub fn check_fat_layout(fat: &FatBinary) -> Result<(), String> {
    cxx::let_cxx_string!(error = "");
    unsafe {
        if ffi::MachO_Utils::check_layout_fat(fat.as_ffi(), error.as_mut().get_unchecked_mut()) {
            return Ok(());
        }
    }
    Err(error.to_string())
}

/// Check if the given file is a FAT Mach-O
pub fn is_fat<P: AsRef<Path>>(path: P) -> bool {
    ffi::MachO_Utils::is_fat(path.as_ref().to_str().unwrap().to_string())
}

/// Check if the given file is a 64-bit Mach-O
pub fn is_64<P: AsRef<Path>>(path: P) -> bool {
    ffi::MachO_Utils::is_64(path.as_ref().to_str().unwrap().to_string())
}

/// Mach-O magic values
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum MachOType {
    /// 32-bit big-endian magic
    MAGIC,
    /// 32-bit little-endian magic
    CIGAM,
    /// 64-bit big-endian magic
    MAGIC_64,
    /// 64-bit little-endian magic
    CIGAM_64,
    /// Big-endian fat magic
    MAGIC_FAT,
    /// Little-endian fat magic
    CIGAM_FAT,
    /// Neural model magic
    NEURAL_MODEL,
    UNKNOWN(u32),
}

impl From<u32> for MachOType {
    fn from(value: u32) -> Self {
        match value {
            0xFEEDFACE => MachOType::MAGIC,
            0xCEFAEDFE => MachOType::CIGAM,
            0xFEEDFACF => MachOType::MAGIC_64,
            0xCFFAEDFE => MachOType::CIGAM_64,
            0xCAFEBABE => MachOType::MAGIC_FAT,
            0xBEBAFECA => MachOType::CIGAM_FAT,
            0xBEEFFACE => MachOType::NEURAL_MODEL,
            _ => MachOType::UNKNOWN(value),
        }
    }
}

impl From<MachOType> for u32 {
    fn from(value: MachOType) -> u32 {
        match value {
            MachOType::MAGIC => 0xFEEDFACE,
            MachOType::CIGAM => 0xCEFAEDFE,
            MachOType::MAGIC_64 => 0xFEEDFACF,
            MachOType::CIGAM_64 => 0xCFFAEDFE,
            MachOType::MAGIC_FAT => 0xCAFEBABE,
            MachOType::CIGAM_FAT => 0xBEBAFECA,
            MachOType::NEURAL_MODEL => 0xBEEFFACE,
            MachOType::UNKNOWN(v) => v,
        }
    }
}
