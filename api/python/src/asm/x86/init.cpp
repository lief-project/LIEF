#include "asm/x86/init.hpp"
namespace LIEF::assembly::x86 {
enum class OPCODE;
class Instruction;
}

namespace LIEF::assembly::x86::py {
void init(nb::module_& m) {
  nb::module_ mod = m.def_submodule("x86");

  create<OPCODE>(mod);
  create<Instruction>(mod);
}
}
