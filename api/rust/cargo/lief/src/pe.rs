//! Module for the PE file format support in LIEF.
//!
//! The [`Binary`] structure exposes the main API to inspect a PE file. It can be instantiated,
//! using either: [`crate::pe::parse`], [`crate::pe::Binary::parse`] or [`crate::Binary::parse`]
//!
//! ```
//! let pe = lief::elf::parse("demo.exe").unwrap();
//! for section in elf.sections() {
//!     println!("section: {}", section.name());
//! }
//! ```

pub mod binary;
pub mod data_directory;
pub mod debug;
pub mod delay_import;
pub mod export;
pub mod headers;
pub mod import;
pub mod load_configuration;
pub mod relocation;
pub mod resources;
pub mod rich_header;
pub mod section;
pub mod signature;
pub mod tls;
pub mod code_integrity;
pub mod builder;
pub mod coff;
pub mod symbol;
pub mod exception;
pub mod exception_x64;
pub mod exception_aarch64;
pub mod chpe_metadata_arm64;
pub mod chpe_metadata_x86;
pub mod dynamic_relocation;
pub mod dynamic_fixups;
pub mod enclave_configuration;
pub mod volatile_metadata;
pub mod parser_config;

#[doc(inline)]
pub use binary::Binary;
#[doc(inline)]
pub use data_directory::DataDirectory;
#[doc(inline)]
pub use delay_import::DelayImport;
#[doc(inline)]
pub use export::Export;
#[doc(inline)]
pub use headers::{DosHeader, Header, OptionalHeader};
#[doc(inline)]
pub use relocation::Relocation;
#[doc(inline)]
pub use resources::Manager as ResourcesManager;
#[doc(inline)]
pub use resources::Node as ResourceNode;
#[doc(inline)]
pub use rich_header::{RichEntry, RichHeader};
#[doc(inline)]
pub use section::Section;
#[doc(inline)]
pub use tls::TLS;
#[doc(inline)]
pub use import::Import;
#[doc(inline)]
pub use signature::Signature;
#[doc(inline)]
pub use coff::String as COFFString;
#[doc(inline)]
pub use symbol::Symbol;
#[doc(inline)]
pub use exception::{RuntimeExceptionFunction, ExceptionInfo};
#[doc(inline)]
pub use load_configuration::{LoadConfiguration, CHPEMetadata};
#[doc(inline)]
pub use dynamic_relocation::DynamicRelocation;
#[doc(inline)]
pub use dynamic_fixups::DynamicFixup;
#[doc(inline)]
pub use enclave_configuration::{EnclaveConfiguration, EnclaveImport};
#[doc(inline)]
pub use volatile_metadata::VolatileMetadata;
#[doc(inline)]
pub use parser_config::Config as ParserConfig;

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
pub fn parse(path: &str) -> Option<Binary> {
    Binary::parse(path)
}
