//! # LIEF
//!
//! ![LIEF Design](https://raw.githubusercontent.com/lief-project/LIEF/main/.github/images/architecture.png)
//!
//! This package provides Rust bindings for [LIEF](https://lief.re). It exposes most of the
//! LIEF API to **read** these formats:
//! - ELF
//! - PE
//! - Mach-O
//!
//! The bindings require at least Rust version **1.74.0** with the 2021 edition and support:
//! - Windows x86-64 (support `/MT` and `/MD` linking)
//! - Linux x86-64/aarch64/musl (Ubuntu 19.10, Almalinux 8, Debian 10, Fedora 29)
//! - macOS (`x86-64` and `aarch64` with at least OSX Big Sur: 11.0)
//! - iOS (`aarch64`)
//!
//! ## Getting Started
//!
//! ```toml
//! [package]
//! name    = "my-awesome-project"
//! version = "0.0.1"
//! edition = "2021"
//!
//! [dependencies]
//! # For nightly
//! lief = { git = "https://github.com/lief-project/LIEF", branch = "main" }
//! # For releases
//! lief = 0.16.0
//! ```
//!
//! ```rust
//! fn main() {
//!    let path = std::env::args().last().unwrap();
//!    let mut file = std::fs::File::open(path).expect("Can't open the file");
//!    match lief::Binary::from(&mut file) {
//!        Some(lief::Binary::ELF(elf)) => {
//!            // Process ELF file
//!        },
//!        Some(lief::Binary::PE(pe)) => {
//!            // Process PE file
//!        },
//!        Some(lief::Binary::MachO(macho)) => {
//!            // Process Mach-O file (including FatMachO)
//!        },
//!        None => {
//!            // Parsing error
//!        }
//!    }
//!    return;
//! }
//! ```
//!
//! Note that the [`generic`] module implements the different traits shared by different structure
//! of executable formats (symbols, relocations, ...)
//!
//! ## Additional Information
//!
//! For more details about the install procedure and the configuration, please check:
//! <https://lief.re/doc/latest/api/rust/index.html>

#![doc(html_no_source)]

pub mod elf;

/// Executable formats generic traits (LIEF's abstract layer)
pub mod generic;

pub mod macho;

pub mod pe;

pub mod pdb;

pub mod dwarf;

pub mod objc;

pub mod dsc;

pub mod debug_info;

pub mod assembly;
mod range;

/// Module for LIEF's error
pub mod error;

pub mod logging;

mod binary;
mod common;

mod debug_location;

#[doc(inline)]
pub use binary::Binary;

#[doc(inline)]
pub use generic::Relocation;

#[doc(inline)]
pub use error::Error;

#[doc(inline)]
pub use debug_info::DebugInfo;

#[doc(inline)]
pub use range::Range;

#[doc(inline)]
pub use debug_location::DebugLocation;

/// Whether it is an extended version of LIEF
pub fn is_extended() -> bool {
    lief_ffi::is_extended()
}

/// Return details about the extended version
pub fn extended_version_info() -> String {
    lief_ffi::extended_version_info().to_string()
}

/// Try to demangle the given input.
///
/// This function requires the extended version of LIEF
pub fn demangle(mangled: &str) -> Result<String, Error> {
    to_conv_result!(
        lief_ffi::demangle,
        *mangled,
        |e: cxx::UniquePtr<cxx::String>| { e.to_string() }
    );
}
