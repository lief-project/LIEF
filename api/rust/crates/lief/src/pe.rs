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

use crate::common::{AsFFI, into_optional};
use crate::enum_from_int;

enum_from_int! {
    /// PE type: 32-bit or 64-bit
    #[allow(non_camel_case_types)]
    PE_TYPE: u32 {
        /// 32-bit PE
        PE32 = 0x10b,
        /// 64-bit PE
        PE32_PLUS = 0x20b,
    }
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    Algorithms: u32 {
        SHA_512 = 0x00000001,
        SHA_384 = 0x00000002,
        SHA_256 = 0x00000003,
        SHA_1 = 0x00000004,
        MD5 = 0x00000005,
        MD4 = 0x00000006,
        MD2 = 0x00000007,
        RSA = 0x00000008,
        EC = 0x00000009,
        MD5_RSA = 0x0000000a,
        SHA1_DSA = 0x0000000b,
        SHA1_RSA = 0x0000000c,
        SHA_256_RSA = 0x0000000d,
        SHA_384_RSA = 0x0000000e,
        SHA_512_RSA = 0x0000000f,
        SHA1_ECDSA = 0x00000010,
        SHA_256_ECDSA = 0x00000011,
        SHA_384_ECDSA = 0x00000012,
        SHA_512_ECDSA = 0x00000013,
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

/// Parse the PE binary at the given memory address
pub fn parse_from_memory(addr: u64) -> Option<Binary> {
    into_optional(ffi::PE_Binary::parse_from_memory(addr))
}

/// Parse the PE binary at the given memory address
pub fn parse_from_memory_with_config(addr: u64, config: &ParserConfig) -> Option<Binary> {
    let ffi_config = config.to_ffi();
    into_optional(ffi::PE_Binary::parse_from_memory_with_config(
        addr,
        &ffi_config,
    ))
}

/// Parse the PE binary from a memory dump located at `path` that was mapped at
/// the virtual address `addr`
pub fn parse_from_dump<P: AsRef<Path>>(path: P, addr: u64) -> Option<Binary> {
    Binary::parse_from_dump(path, addr)
}

/// Same as [`parse_from_dump`] but with a provided configuration
pub fn parse_from_dump_with_config<P: AsRef<Path>>(
    path: P,
    addr: u64,
    config: &ParserConfig,
) -> Option<Binary> {
    Binary::parse_from_dump_with_config(path, addr, config)
}

/// Determine the PE type (PE32 or PE32+) of the given file
pub fn get_type<P: AsRef<Path>>(path: P) -> Option<PE_TYPE> {
    cxx::let_cxx_string!(__cxx_s = path.as_ref().to_str().unwrap_or("").to_string());
    let val = ffi::PE_Utils::get_type(&__cxx_s);
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
    cxx::let_cxx_string!(__cxx_s = oid.to_string());
    ffi::PE_Utils::oid_to_string(&__cxx_s).to_string()
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

enum_from_int! {
    /// Mode used for computing the import hash
    #[allow(non_camel_case_types)]
    ImphashMode: u32 {
        /// Default LIEF implementation
        DEFAULT = 0x00000000,
        /// Use pefile algorithm (same as VirusTotal)
        PEFILE = 0x00000001,
    }
}
