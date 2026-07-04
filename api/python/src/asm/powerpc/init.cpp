#include "asm/powerpc/init.hpp"
namespace LIEF::assembly::powerpc {
enum class OPCODE;
enum class REG;
class Instruction;
class Operand;
}

namespace LIEF::assembly::powerpc::py {
void init(nb::module_& m) {
  nb::module_ mod = m.def_submodule("powerpc");

  create<OPCODE>(mod);
  create<REG>(mod);
  create<Instruction>(mod);
  create<Operand>(mod);
}
}
