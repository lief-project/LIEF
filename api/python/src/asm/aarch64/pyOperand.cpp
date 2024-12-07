#include <ostream>
#include <sstream>

#include "LIEF/asm/aarch64/Operand.hpp"

#include "asm/aarch64/init.hpp"

#include <nanobind/stl/string.h>

#include "pyLIEF.hpp"

namespace LIEF::assembly::aarch64::operands {
class Immediate;
class Register;
class Memory;
class PCRelative;
}

namespace LIEF::assembly::aarch64::py {
template<>
void create<aarch64::Operand>(nb::module_& m) {
  nb::class_<aarch64::Operand> obj(m, "Operand",
    R"doc(This class represents an operand for an AArch64 instruction)doc"_doc
  );

  obj
    .def_prop_ro("to_string", &Operand::to_string,
      R"doc(Pretty representation of the operand)doc"_doc
    )
    LIEF_DEFAULT_STR(aarch64::Operand)
  ;

  nb::module_ operands = m.def_submodule("operands");
  create<aarch64::operands::Immediate>(operands);
  create<aarch64::operands::Register>(operands);
  create<aarch64::operands::Memory>(operands);
  create<aarch64::operands::PCRelative>(operands);
}
}
