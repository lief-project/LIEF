//! Module for the PE file format support in LIEF.
//!
//! The [`Binary`] structure exposes the main API to inspect a PE file. It can be instantiated,
//! using either: [`crate::pe::parse`], [`crate::pe::Binary::parse`] or [`crate::Binary::parse`]
//!
//! ```
//! let pe = lief::pe::parse("demo.exe").unwrap();
//! for section in pe.sections() {
//!     println!("section: {}", section.name());
//! }
//! ```

use lief_ffi as ffi;
use std::path::Path;

pub mod binary;
pub mod builder;
pub mod chpe_metadata_arm64;
pub mod chpe_metadata_x86;
pub mod code_integrity;
pub mod data_directory;
pub mod debug;
pub mod delay_import;
pub mod dynamic_fixups;
pub mod dynamic_relocation;
pub mod enclave_configuration;
pub mod exception;
pub mod exception_aarch64;
pub mod exception_x64;
pub mod export;
pub mod factory;
pub mod headers;
pub mod import;
pub mod load_configuration;
pub mod parser_config;
pub mod relocation;
pub mod resources;
pub mod rich_header;
pub mod section;
pub mod signature;
pub mod tls;
pub mod volatile_metadata;

#[doc(inline)]
pub use binary::Binary;
#[doc(inline)]
pub use data_directory::DataDirectory;
#[doc(inline)]
pub use delay_import::DelayImport;
#[doc(inline)]
pub use dynamic_fixups::DynamicFixup;
#[doc(inline)]
pub use dynamic_relocation::DynamicRelocation;
#[doc(inline)]
pub use enclave_configuration::{EnclaveConfiguration, EnclaveImport};
#[doc(inline)]
pub use exception::{ExceptionInfo, RuntimeExceptionFunction};
#[doc(inline)]
pub use export::Export;
#[doc(inline)]
pub use factory::Factory;
#[doc(inline)]
pub use headers::{DosHeader, Header, OptionalHeader};
#[doc(inline)]
pub use import::Import;
#[doc(inline)]
pub use load_configuration::{CHPEMetadata, LoadConfiguration};
#[doc(inline)]
pub use parser_config::Config as ParserConfig;
#[doc(inline)]
pub use relocation::Relocation;
#[doc(inline)]
pub use resources::Accelerator as ResourceAccelerator;
#[doc(inline)]
pub use resources::Icon as ResourceIcon;
#[doc(inline)]
pub use resources::Manager as ResourcesManager;
#[doc(inline)]
pub use resources::Node as ResourceNode;
#[doc(inline)]
pub use resources::StringEntry as ResourceStringEntry;
#[doc(inline)]
pub use resources::Version as ResourceVersion;
#[doc(inline)]
pub use rich_header::{RichEntry, RichHeader};
#[doc(inline)]
pub use section::Section;
#[doc(inline)]
pub use signature::Signature;
#[doc(inline)]
pub use tls::TLS;
#[doc(inline)]
pub use volatile_metadata::VolatileMetadata;

use crate::common::AsFFI;

/// PE type: 32-bit or 64-bit
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum PE_TYPE {
    /// 32-bit PE
    PE32,
    /// 64-bit PE
    PE32_PLUS,
    UNKNOWN(u32),
}

impl From<u32> for PE_TYPE {
    fn from(value: u32) -> Self {
        match value {
            0x10b => PE_TYPE::PE32,
            0x20b => PE_TYPE::PE32_PLUS,
            _ => PE_TYPE::UNKNOWN(value),
        }
    }
}

impl From<PE_TYPE> for u32 {
    fn from(value: PE_TYPE) -> u32 {
        match value {
            PE_TYPE::PE32 => 0x10b,
            PE_TYPE::PE32_PLUS => 0x20b,
            PE_TYPE::UNKNOWN(v) => v,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Algorithms {
    SHA_512,
    SHA_384,
    SHA_256,
    SHA_1,
    MD5,
    MD4,
    MD2,
    RSA,
    EC,
    MD5_RSA,
    SHA1_DSA,
    SHA1_RSA,
    SHA_256_RSA,
    SHA_384_RSA,
    SHA_512_RSA,
    SHA1_ECDSA,
    SHA_256_ECDSA,
    SHA_384_ECDSA,
    SHA_512_ECDSA,
    UNKNOWN(u32),
}

impl From<u32> for Algorithms {
    fn from(value: u32) -> Self {
        match value {
            0x00000001 => Algorithms::SHA_512,
            0x00000002 => Algorithms::SHA_384,
            0x00000003 => Algorithms::SHA_256,
            0x00000004 => Algorithms::SHA_1,
            0x00000005 => Algorithms::MD5,
            0x00000006 => Algorithms::MD4,
            0x00000007 => Algorithms::MD2,
            0x00000008 => Algorithms::RSA,
            0x00000009 => Algorithms::EC,
            0x0000000a => Algorithms::MD5_RSA,
            0x0000000b => Algorithms::SHA1_DSA,
            0x0000000c => Algorithms::SHA1_RSA,
            0x0000000d => Algorithms::SHA_256_RSA,
            0x0000000e => Algorithms::SHA_384_RSA,
            0x0000000f => Algorithms::SHA_512_RSA,
            0x00000010 => Algorithms::SHA1_ECDSA,
            0x00000011 => Algorithms::SHA_256_ECDSA,
            0x00000012 => Algorithms::SHA_384_ECDSA,
            0x00000013 => Algorithms::SHA_512_ECDSA,
            _ => Algorithms::UNKNOWN(value),
        }
    }
}

impl From<Algorithms> for u32 {
    fn from(value: Algorithms) -> u32 {
        match value {
            Algorithms::SHA_512 => 0x00000001,
            Algorithms::SHA_384 => 0x00000002,
            Algorithms::SHA_256 => 0x00000003,
            Algorithms::SHA_1 => 0x00000004,
            Algorithms::MD5 => 0x00000005,
            Algorithms::MD4 => 0x00000006,
            Algorithms::MD2 => 0x00000007,
            Algorithms::RSA => 0x00000008,
            Algorithms::EC => 0x00000009,
            Algorithms::MD5_RSA => 0x0000000a,
            Algorithms::SHA1_DSA => 0x0000000b,
            Algorithms::SHA1_RSA => 0x0000000c,
            Algorithms::SHA_256_RSA => 0x0000000d,
            Algorithms::SHA_384_RSA => 0x0000000e,
            Algorithms::SHA_512_RSA => 0x0000000f,
            Algorithms::SHA1_ECDSA => 0x00000010,
            Algorithms::SHA_256_ECDSA => 0x00000011,
            Algorithms::SHA_384_ECDSA => 0x00000012,
            Algorithms::SHA_512_ECDSA => 0x00000013,
            Algorithms::UNKNOWN(_) => 0,
        }
    }
}

/// Parse a PE file from the given file path
pub fn parse<P: AsRef<Path>>(path: P) -> Option<Binary> {
    Binary::parse(path)
}

/// Parse a PE file from the given file path and configuration
pub fn parse_with_config<P: AsRef<Path>>(path: P, config: &ParserConfig) -> Option<Binary> {
    Binary::parse_with_config(path, config)
}

/// Check that the layout of the given binary is correct from the Windows loader
/// perspective
pub fn check_layout(binary: &Binary) -> Result<(), String> {
    cxx::let_cxx_string!(error = "");
    unsafe {
        if ffi::PE_Utils::check_layout(binary.as_ffi(), error.as_mut().get_unchecked_mut()) {
            return Ok(());
        }
    }
    Err(error.to_string())
}

/// Determine the PE type (PE32 or PE32+) of the given file
pub fn get_type<P: AsRef<Path>>(path: P) -> Option<PE_TYPE> {
    let val = ffi::PE_Utils::get_type(path.as_ref().to_str().unwrap_or("").to_string());
    if val == 0 {
        return None;
    }
    Some(PE_TYPE::from(val))
}

/// Compute the import hash of the given binary
pub fn get_imphash(binary: &Binary, mode: ImphashMode) -> String {
    ffi::PE_Utils::get_imphash(binary.as_ffi(), mode.into()).to_string()
}

/// Convert an OID string to a human-readable string
pub fn oid_to_string(oid: &str) -> String {
    ffi::PE_Utils::oid_to_string(oid.to_string()).to_string()
}

/// Try to resolve import ordinals using the well-known ordinal lookup table
pub fn resolve_ordinals<'a>(
    imp: &'a Import<'a>,
    strict: bool,
    use_std: bool,
) -> Option<Import<'a>> {
    crate::common::into_optional(ffi::PE_Utils::resolve_ordinals(
        imp.as_ffi(),
        strict,
        use_std,
    ))
}

/// Mode used for computing the import hash
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ImphashMode {
    /// Default LIEF implementation
    DEFAULT,
    /// Use pefile algorithm (same as VirusTotal)
    PEFILE,
    UNKNOWN(u32),
}

impl From<u32> for ImphashMode {
    fn from(value: u32) -> Self {
        match value {
            0x00000000 => ImphashMode::DEFAULT,
            0x00000001 => ImphashMode::PEFILE,
            _ => ImphashMode::UNKNOWN(value),
        }
    }
}

impl From<ImphashMode> for u32 {
    fn from(value: ImphashMode) -> u32 {
        match value {
            ImphashMode::DEFAULT => 0x00000000,
            ImphashMode::PEFILE => 0x00000001,
            ImphashMode::UNKNOWN(v) => v,
        }
    }
}
