#include "LIEF/asm/riscv/Instruction.hpp"

#include "asm/riscv/init.hpp"

namespace LIEF::assembly::riscv::py {
template<>
void create<riscv::Instruction>(nb::module_& m) {
  nb::class_<riscv::Instruction, assembly::Instruction> obj(m, "Instruction",
    R"doc(This class represents a RISC-V (32 or 64 bit) instruction)doc"_doc
  );

  obj
    .def_prop_ro("opcode", &Instruction::opcode,
      R"doc(The instruction opcode as defined in LLVM)doc"_doc
    )
  ;
}
}
