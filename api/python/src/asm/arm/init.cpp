#include "asm/arm/init.hpp"
namespace LIEF::assembly::arm {
enum class OPCODE;
class Instruction;
}

namespace LIEF::assembly::arm::py {
void init(nb::module_& m) {
  nb::module_ mod = m.def_submodule("arm");

  create<OPCODE>(mod);
  create<Instruction>(mod);
}
}
