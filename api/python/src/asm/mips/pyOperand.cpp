#include <ostream>
#include <sstream>

#include "LIEF/asm/mips/Operand.hpp"

#include "asm/mips/init.hpp"

#include <nanobind/stl/string.h>

#include "pyLIEF.hpp"

namespace LIEF::assembly::mips::operands {
class Immediate;
class Register;
class Memory;
class PCRelative;
}

namespace LIEF::assembly::mips::py {
template<>
void create<mips::Operand>(nb::module_& m) {
  nb::class_<mips::Operand> obj(
      m, "Operand", "This class represents an operand for a Mips instruction"_doc
  );

  obj.def_prop_ro("to_string", &Operand::to_string,
                  "Pretty representation of the operand"_doc)
      .LIEF_DEFAULT_STR(mips::Operand);

  nb::module_ operands = m.def_submodule("operands");
  create<mips::operands::Immediate>(operands);
  create<mips::operands::Register>(operands);
  create<mips::operands::Memory>(operands);
  create<mips::operands::PCRelative>(operands);
}
}
