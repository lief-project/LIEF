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

pub mod instruction;

#[doc(inline)]
pub use instruction::{Instructions, Instruction};
