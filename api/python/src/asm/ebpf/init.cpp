#include "asm/ebpf/init.hpp"
namespace LIEF::assembly::ebpf {
enum class OPCODE;
class Instruction;
}

namespace LIEF::assembly::ebpf::py {
void init(nb::module_& m) {
  nb::module_ mod = m.def_submodule("ebpf");

  create<OPCODE>(mod);
  create<Instruction>(mod);
}
}
