#include "asm/mips/init.hpp"
namespace LIEF::assembly::mips {
enum class OPCODE;
enum class REG;
class Instruction;
class Operand;
}

namespace LIEF::assembly::mips::py {
void init(nb::module_& m) {
  nb::module_ mod = m.def_submodule("mips");

  create<OPCODE>(mod);
  create<REG>(mod);
  create<Instruction>(mod);
  create<Operand>(mod);
}
}
