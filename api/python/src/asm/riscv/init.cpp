#include "asm/riscv/init.hpp"
namespace LIEF::assembly::riscv {
enum class OPCODE;
class Instruction;
}

namespace LIEF::assembly::riscv::py {
void init(nb::module_& m) {
  nb::module_ mod = m.def_submodule("riscv");

  create<OPCODE>(mod);
  create<Instruction>(mod);
}
}
