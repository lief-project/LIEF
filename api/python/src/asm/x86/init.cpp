#include "asm/x86/init.hpp"
namespace LIEF::assembly::x86 {
enum class OPCODE;
enum class REG;
class Instruction;
class Operand;
}

namespace LIEF::assembly::x86::py {
void init(nb::module_& m) {
  nb::module_ mod = m.def_submodule("x86");

  create<OPCODE>(mod);
  create<REG>(mod);
  create<Instruction>(mod);
  create<Operand>(mod);
}
}
