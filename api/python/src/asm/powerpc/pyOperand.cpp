#include <ostream>
#include <sstream>

#include "LIEF/asm/powerpc/Operand.hpp"

#include "asm/powerpc/init.hpp"

#include <nanobind/stl/string.h>

#include "pyLIEF.hpp"

namespace LIEF::assembly::powerpc::operands {
class Immediate;
class Register;
class Memory;
class PCRelative;
}

namespace LIEF::assembly::powerpc::py {
template<>
void create<powerpc::Operand>(nb::module_& m) {
  nb::class_<powerpc::Operand> obj(m, "Operand",
    R"doc(This class represents an operand for a PowerPC instruction)doc"_doc
  );

  obj
    .def_prop_ro("to_string", &Operand::to_string,
      R"doc(Pretty representation of the operand)doc"_doc
    )
    LIEF_DEFAULT_STR(powerpc::Operand)
  ;

  nb::module_ operands = m.def_submodule("operands");
  create<powerpc::operands::Immediate>(operands);
  create<powerpc::operands::Register>(operands);
  create<powerpc::operands::Memory>(operands);
  create<powerpc::operands::PCRelative>(operands);
}
}
