//! x86/x86-64 architecture-related namespace

pub mod instruction;
pub mod opcodes;
pub mod operands;
pub mod registers;

#[doc(inline)]
pub use opcodes::Opcode;

#[doc(inline)]
pub use instruction::Instruction;

#[doc(inline)]
pub use operands::Operands;

#[doc(inline)]
pub use operands::Operand;
