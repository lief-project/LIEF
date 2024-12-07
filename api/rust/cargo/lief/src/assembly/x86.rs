//! x86/x86-64 architecture-related namespace

pub mod opcodes;
pub mod instruction;
pub mod registers;
pub mod operands;

#[doc(inline)]
pub use opcodes::Opcode;

#[doc(inline)]
pub use instruction::Instruction;

#[doc(inline)]
pub use operands::Operands;

#[doc(inline)]
pub use operands::Operand;
