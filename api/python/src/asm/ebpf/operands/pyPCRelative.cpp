#include "asm/ebpf/init.hpp"
#include "LIEF/asm/ebpf/operands/PCRelative.hpp"

namespace LIEF::assembly::ebpf::py {
template<>
void create<ebpf::operands::PCRelative>(nb::module_& m) {
  nb::class_<ebpf::operands::PCRelative, ebpf::Operand> obj(m, "PCRelative",
    R"doc(
    This class represents a PC-relative operand.

    .. code-block:: text

      if r1 == 0 goto +5
                      |
                      v
              PC Relative operand
    )doc"_doc
  );

  obj
    .def_prop_ro("value", &ebpf::operands::PCRelative::value,
      R"doc(
      The effective value that is relative to the current ``pc`` register
      )doc"_doc
    )
  ;
}
}
