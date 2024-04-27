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
//! - Linux x86-64  (Ubuntu 20.04, Almalinux 9, Debian 11.5, Fedora 29)
//! - macOS (`x86-64` and `aarch64` with at least OSX Big Sur: 11.0)
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
//! lief = 0.15.0
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

#![doc(html_no_source)]
pub mod elf;
pub mod generic;
pub mod macho;
pub mod pe;

mod binary;
mod common;

#[doc(inline)]
pub use binary::Binary;
