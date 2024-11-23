#include "LIEF/asm/aarch64/Instruction.hpp"

#include "asm/aarch64/init.hpp"

namespace LIEF::assembly::aarch64::py {
template<>
void create<aarch64::Instruction>(nb::module_& m) {
  nb::class_<aarch64::Instruction, assembly::Instruction> obj(m, "Instruction",
    R"doc(
    This class represents an AArch64 instruction
    )doc"_doc
  );

  obj
    .def_prop_ro("opcode", &Instruction::opcode,
      R"doc(The instruction opcode as defined in LLVM)doc"_doc
    )
  ;
}
}
