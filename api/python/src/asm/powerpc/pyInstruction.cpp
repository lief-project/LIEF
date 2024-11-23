#include "LIEF/asm/powerpc/Instruction.hpp"

#include "asm/powerpc/init.hpp"

namespace LIEF::assembly::powerpc::py {
template<>
void create<powerpc::Instruction>(nb::module_& m) {
  nb::class_<powerpc::Instruction, assembly::Instruction> obj(m, "Instruction",
    R"doc(This class represents a PowerPC (ppc64/ppc32) instruction)doc"_doc
  );

  obj
    .def_prop_ro("opcode", &Instruction::opcode,
      R"doc(The instruction opcode as defined in LLVM)doc"_doc
    )
  ;
}
}
