#include "asm/ebpf/init.hpp"
namespace LIEF::assembly::ebpf {
enum class OPCODE;
enum class REG;
class Instruction;
class Operand;
}

namespace LIEF::assembly::ebpf::py {
void init(nb::module_& m) {
  nb::module_ mod = m.def_submodule("ebpf");

  create<OPCODE>(mod);
  create<REG>(mod);
  create<Instruction>(mod);
  create<Operand>(mod);
}
}
