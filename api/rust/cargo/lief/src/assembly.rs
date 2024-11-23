//! Assembly/Disassembly Module
//!
//! ### Getting Started
//!
//! One can start disassembling code by using the different functions exposes in the
//! [`crate::generic::Binary`] trait:
//!
//! ```
//! fn disassemble(target: &dyn lief::generic::Binary) {
//!     for inst in target.disassemble_symbol("_entrypoint") {
//!         println!("{}", inst.to_string());
//!     }
//! }
//! ```
//!
//! An instruction is represented by the enum: [`Instructions`] which implements the **trait**
//! [`Instruction`].
//!
//! For architecture-dependant API, you can check the following structures:
//!
//! - [`aarch64::Instruction`]
//! - [`x86::Instruction`]
//! - [`arm::Instruction`]
//! - [`powerpc::Instruction`]
//! - [`riscv::Instruction`]
//! - [`mips::Instruction`]
//! - [`ebpf::Instruction`]

pub mod instruction;
pub mod aarch64;
pub mod x86;
pub mod arm;
pub mod powerpc;
pub mod riscv;
pub mod mips;
pub mod ebpf;

#[doc(inline)]
pub use instruction::{Instructions, Instruction};
