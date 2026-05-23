//! Mips architecture-related namespace

pub mod instruction;
pub mod opcodes;
pub mod registers;

#[doc(inline)]
pub use opcodes::Opcode;

#[doc(inline)]
pub use instruction::Instruction;
