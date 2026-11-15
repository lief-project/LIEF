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
pub mod builder;
pub mod commands;
pub mod export_info;
pub mod fat_binary;
pub mod header;
pub mod parser_config;
pub mod relocation;
pub mod section;
pub mod stub;
pub mod symbol;
pub mod thread_local_variables;

use lief_ffi as ffi;
use std::path::Path;

#[doc(inline)]
pub use binary::Binary;
#[doc(inline)]
pub use binding_info::BindingInfo;
#[doc(inline)]
pub use commands::Commands;
#[doc(inline)]
pub use export_info::ExportInfo;
#[doc(inline)]
pub use fat_binary::FatBinary;
#[doc(inline)]
pub use header::Header;
#[doc(inline)]
pub use relocation::Relocation;
#[doc(inline)]
pub use section::Generic;
#[doc(inline)]
pub use section::MachOSection;
#[doc(inline)]
pub use section::Section;
#[doc(inline)]
pub use stub::Stub;
#[doc(inline)]
pub use symbol::Symbol;
#[doc(inline)]
pub use thread_local_variables::ThreadLocalVariables;

use crate::common::AsFFI;
use crate::enum_from_int;

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

/// Parse a Mach-O binary from a memory dump located at `path` that was mapped
/// at the virtual address `addr`
pub fn parse_from_dump<P: AsRef<Path>>(path: P, addr: u64) -> Option<FatBinary> {
    FatBinary::parse_from_dump(path, addr)
}

/// Same as [`parse_from_dump`] but with a provided configuration
pub fn parse_from_dump_with_config<P: AsRef<Path>>(
    path: P,
    addr: u64,
    config: &ParserConfig,
) -> Option<FatBinary> {
    FatBinary::parse_from_dump_with_config(path, addr, config)
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
    cxx::let_cxx_string!(__cxx_s = path.as_ref().to_str().unwrap().to_string());
    ffi::MachO_Utils::is_fat(&__cxx_s)
}

/// Check if the given file is a 64-bit Mach-O
pub fn is_64<P: AsRef<Path>>(path: P) -> bool {
    cxx::let_cxx_string!(__cxx_s = path.as_ref().to_str().unwrap().to_string());
    ffi::MachO_Utils::is_64(&__cxx_s)
}

enum_from_int! {
    /// Mach-O magic values
    #[allow(non_camel_case_types)]
    MachOType: u32 {
        /// 32-bit big-endian magic
        MAGIC = 0xFEEDFACE,
        /// 32-bit little-endian magic
        CIGAM = 0xCEFAEDFE,
        /// 64-bit big-endian magic
        MAGIC_64 = 0xFEEDFACF,
        /// 64-bit little-endian magic
        CIGAM_64 = 0xCFFAEDFE,
        /// Big-endian fat magic
        MAGIC_FAT = 0xCAFEBABE,
        /// Little-endian fat magic
        CIGAM_FAT = 0xBEBAFECA,
        /// Neural model magic
        NEURAL_MODEL = 0xBEEFFACE,
    }
}
