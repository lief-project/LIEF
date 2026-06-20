#include "asm/riscv/init.hpp"
namespace LIEF::assembly::riscv {
enum class OPCODE;
enum class REG;
enum class SYSREG;
class Instruction;
class Operand;
}

namespace LIEF::assembly::riscv::py {
void init(nb::module_& m) {
  nb::module_ mod = m.def_submodule("riscv");

  create<OPCODE>(mod);
  create<REG>(mod);
  create<SYSREG>(mod);
  create<Instruction>(mod);
  create<Operand>(mod);
}
}
