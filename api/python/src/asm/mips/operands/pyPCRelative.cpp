#include "asm/mips/init.hpp"
#include "LIEF/asm/mips/operands/PCRelative.hpp"

namespace LIEF::assembly::mips::py {
template<>
void create<mips::operands::PCRelative>(nb::module_& m) {
  nb::class_<mips::operands::PCRelative, mips::Operand> obj(m, "PCRelative",
    R"doc(
    This class represents a PC-relative operand.

    .. code-block:: text

      bal 0x100
          |
          v
       PC Relative operand
    )doc"_doc
  );

  obj
    .def_prop_ro("value", &mips::operands::PCRelative::value,
      R"doc(
      The effective value that is relative to the current ``pc`` register
      )doc"_doc
    )
  ;
}
}
