#include "asm/mips/init.hpp"
namespace LIEF::assembly::mips {
enum class OPCODE;
class Instruction;
}

namespace LIEF::assembly::mips::py {
void init(nb::module_& m) {
  nb::module_ mod = m.def_submodule("mips");

  create<OPCODE>(mod);
  create<Instruction>(mod);
}
}
