#include <ostream>
#include <sstream>

#include "LIEF/asm/ebpf/Operand.hpp"

#include "asm/ebpf/init.hpp"

#include <nanobind/stl/string.h>

#include "pyLIEF.hpp"

namespace LIEF::assembly::ebpf::operands {
class Immediate;
class Register;
class Memory;
class PCRelative;
}

namespace LIEF::assembly::ebpf::py {
template<>
void create<ebpf::Operand>(nb::module_& m) {
  nb::class_<ebpf::Operand> obj(m, "Operand",
    R"doc(This class represents an operand for an eBPF instruction)doc"_doc
  );

  obj
    .def_prop_ro("to_string", &Operand::to_string,
      R"doc(Pretty representation of the operand)doc"_doc
    )
    LIEF_DEFAULT_STR(ebpf::Operand)
  ;

  nb::module_ operands = m.def_submodule("operands");
  create<ebpf::operands::Immediate>(operands);
  create<ebpf::operands::Register>(operands);
  create<ebpf::operands::Memory>(operands);
  create<ebpf::operands::PCRelative>(operands);
}
}
