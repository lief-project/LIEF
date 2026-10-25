#include "LIEF/asm/arm/Instruction.hpp"

#include "asm/arm/init.hpp"

namespace LIEF::assembly::arm::py {
template<>
void create<arm::Instruction>(nb::module_& m) {
  nb::class_<arm::Instruction, assembly::Instruction> obj(
      m, "Instruction", "This class represents an ARM/Thumb instruction"_doc
  );

  obj.attr("__match_args__") = nb::make_tuple("opcode");

  obj.def_prop_ro("opcode", &Instruction::opcode,
                  "The instruction opcode as defined in LLVM"_doc);
}
}
