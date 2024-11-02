#include "asm/init.hpp"
#include "asm/pyAssembly.hpp"


namespace LIEF::assembly {
class Engine;
class Instruction;
}

namespace LIEF::assembly::py {
void init(nb::module_& m) {
  nb::module_ mod = m.def_submodule("assembly");

  create<LIEF::assembly::Engine>(mod);
  create<LIEF::assembly::Instruction>(mod);
}
}
