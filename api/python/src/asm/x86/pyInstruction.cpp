#include "LIEF/asm/x86/Instruction.hpp"

#include "asm/x86/init.hpp"

namespace LIEF::assembly::x86::py {
template<>
void create<x86::Instruction>(nb::module_& m) {
  nb::class_<x86::Instruction, assembly::Instruction> obj(m, "Instruction",
    R"doc(This class represents a x86/x86-64 instruction)doc"_doc
  );

  obj
    .def_prop_ro("opcode", &Instruction::opcode,
      R"doc(The instruction opcode as defined in LLVM)doc"_doc
    )
  ;
}
}
