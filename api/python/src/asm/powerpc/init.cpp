#include "asm/powerpc/init.hpp"
namespace LIEF::assembly::powerpc {
enum class OPCODE;
class Instruction;
}

namespace LIEF::assembly::powerpc::py {
void init(nb::module_& m) {
  nb::module_ mod = m.def_submodule("powerpc");

  create<OPCODE>(mod);
  create<Instruction>(mod);
}
}
