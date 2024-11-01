//! Module for Objective-C metadata
//!
//! This module contains the support of Objective-C metadata embedded in Mach-O
//! [`crate::macho::Binary`].
//!
//! One can access this metadata using the [`crate::macho::Binary::objc_metadata`] function
//!
//! ```
//! fn inspect_objc(macho: &lief::macho::Binary) {
//!     let metadata: lief::objc::Metadata = macho.objc_metadata().expect("Can't access metadata");
//!     for class in metadata.classes() {
//!         println!("{}", class.to_decl());
//!     }
//! }
//! ```

pub mod metadata;
pub mod class;
pub mod protocol;
pub mod method;
pub mod property;
pub mod ivar;
pub mod decl_opt;

#[doc(inline)]
pub use metadata::Metadata;

#[doc(inline)]
pub use class::Class;

#[doc(inline)]
pub use method::Method;

#[doc(inline)]
pub use property::Property;

#[doc(inline)]
pub use protocol::Protocol;

#[doc(inline)]
pub use ivar::IVar;

#[doc(inline)]
pub use decl_opt::DeclOpt;
