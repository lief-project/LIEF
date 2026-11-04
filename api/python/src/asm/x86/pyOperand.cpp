#include "LIEF/asm/x86/Operand.hpp"

#include "asm/x86/init.hpp"

#include <nanobind/stl/string.h>

#include "pyLIEF.hpp"

namespace LIEF::assembly::x86::operands {
class Immediate;
class Register;
class Memory;
class PCRelative;
}

namespace LIEF::assembly::x86::py {
template<>
void create<x86::Operand>(nb::module_& m) {
  nb::class_<x86::Operand> obj(
      m, "Operand",
      "This class represents an operand for an x86/x86-64 instruction"_doc
  );

  obj.def_prop_ro("to_string", &Operand::to_string,
                  "Pretty representation of the operand"_doc)
      .LIEF_DEFAULT_STR(x86::Operand);

  nb::module_ operands = m.def_submodule("operands");
  create<x86::operands::Immediate>(operands);
  create<x86::operands::Register>(operands);
  create<x86::operands::Memory>(operands);
  create<x86::operands::PCRelative>(operands);
}
}
