#include "LIEF/asm/mips/Instruction.hpp"

#include "asm/mips/init.hpp"

namespace LIEF::assembly::mips::py {
template<>
void create<mips::Instruction>(nb::module_& m) {
  nb::class_<mips::Instruction, assembly::Instruction> obj(m, "Instruction",
    R"doc(This class represents a Mips instruction (including mips64, mips32))doc"_doc
  );

  obj
    .def_prop_ro("opcode", &Instruction::opcode,
      R"doc(The instruction opcode as defined in LLVM)doc"_doc
    )
  ;
}
}
