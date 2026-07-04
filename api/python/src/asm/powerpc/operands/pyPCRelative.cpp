#include "asm/powerpc/init.hpp"
#include "LIEF/asm/powerpc/operands/PCRelative.hpp"

namespace LIEF::assembly::powerpc::py {
template<>
void create<powerpc::operands::PCRelative>(nb::module_& m) {
  nb::class_<powerpc::operands::PCRelative, powerpc::Operand> obj(m, "PCRelative",
    R"doc(
    This class represents a PC-relative operand.

    .. code-block:: text

      bl 0x100
         |
         v
       PC Relative operand
    )doc"_doc
  );

  obj
    .def_prop_ro("value", &powerpc::operands::PCRelative::value,
      R"doc(
      The effective value that is relative to the current ``pc`` register
      )doc"_doc
    )
  ;
}
}
