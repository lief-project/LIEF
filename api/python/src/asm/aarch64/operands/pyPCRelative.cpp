#include "asm/aarch64/init.hpp"
#include "LIEF/asm/aarch64/operands/PCRelative.hpp"

namespace LIEF::assembly::aarch64::py {
template<>
void create<aarch64::operands::PCRelative>(nb::module_& m) {
  nb::class_<aarch64::operands::PCRelative, aarch64::Operand> obj(m, "PCRelative",
    R"doc(
    This class represents a PC-relative operand.

    .. code-block:: text

      ldr x0, #8
              |
              v
       PC Relative operand
    )doc"_doc
  );

  obj
    .def_prop_ro("value", &aarch64::operands::PCRelative::value,
      R"doc(
      The effective value that is relative to the current ``pc`` register
      )doc"_doc
    )
  ;
}
}
