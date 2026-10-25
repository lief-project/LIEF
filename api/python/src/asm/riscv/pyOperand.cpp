#include <ostream>
#include <sstream>

#include "LIEF/asm/riscv/Operand.hpp"

#include "asm/riscv/init.hpp"

#include <nanobind/stl/string.h>

#include "pyLIEF.hpp"

namespace LIEF::assembly::riscv::operands {
class Immediate;
class Register;
class Memory;
class PCRelative;
}

namespace LIEF::assembly::riscv::py {
template<>
void create<riscv::Operand>(nb::module_& m) {
  nb::class_<riscv::Operand> obj(
      m, "Operand", "This class represents an operand for a RISC-V instruction"_doc
  );

  obj.def_prop_ro("to_string", &Operand::to_string,
                  "Pretty representation of the operand"_doc)
      .LIEF_DEFAULT_STR(riscv::Operand);

  nb::module_ operands = m.def_submodule("operands");
  create<riscv::operands::Immediate>(operands);
  create<riscv::operands::Register>(operands);
  create<riscv::operands::Memory>(operands);
  create<riscv::operands::PCRelative>(operands);
}
}
