#include "asm/aarch64/init.hpp"
namespace LIEF::assembly::aarch64 {
enum class OPCODE;
enum class REG;
enum class SYSREG;
class Instruction;
class Operand;
}

namespace LIEF::assembly::aarch64::py {
void init(nb::module_& m) {
  nb::module_ mod = m.def_submodule("aarch64");

  create<OPCODE>(mod);
  create<REG>(mod);
  create<SYSREG>(mod);
  create<Instruction>(mod);
  create<Operand>(mod);
}
}
