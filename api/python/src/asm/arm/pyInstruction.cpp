#include "LIEF/asm/arm/Instruction.hpp"

#include "asm/arm/init.hpp"

namespace LIEF::assembly::arm::py {
template<>
void create<arm::Instruction>(nb::module_& m) {
  nb::class_<arm::Instruction, assembly::Instruction> obj(m, "Instruction",
    R"doc(This class represents an ARM/Thumb instruction)doc"_doc
  );

  obj
    .def_prop_ro("opcode", &Instruction::opcode,
      R"doc(The instruction opcode as defined in LLVM)doc"_doc
    )
  ;
}
}
