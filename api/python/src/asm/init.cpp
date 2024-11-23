#include "asm/init.hpp"
#include "asm/pyAssembly.hpp"

#include "asm/aarch64/init.hpp"
#include "asm/x86/init.hpp"
#include "asm/riscv/init.hpp"
#include "asm/mips/init.hpp"
#include "asm/powerpc/init.hpp"
#include "asm/arm/init.hpp"
#include "asm/ebpf/init.hpp"

namespace LIEF::assembly {
class Engine;
class Instruction;
}

namespace LIEF::assembly::py {
void init(nb::module_& m) {
  nb::module_ mod = m.def_submodule("assembly");

  create<LIEF::assembly::Engine>(mod);
  create<LIEF::assembly::Instruction>(mod);

  aarch64::py::init(mod);
  x86::py::init(mod);
  arm::py::init(mod);
  ebpf::py::init(mod);
  powerpc::py::init(mod);
  mips::py::init(mod);
  riscv::py::init(mod);
}
}
