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

use num_derive::{FromPrimitive, ToPrimitive};

#[allow(non_camel_case_types)]
#[derive(FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum Algorithms {
    UNKNOWN = 0,
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
}
