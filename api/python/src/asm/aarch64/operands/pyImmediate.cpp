#include "asm/aarch64/init.hpp"
#include "LIEF/asm/aarch64/operands/Immediate.hpp"

namespace LIEF::assembly::aarch64::py {
template<>
void create<aarch64::operands::Immediate>(nb::module_& m) {
  nb::class_<aarch64::operands::Immediate, aarch64::Operand> obj(m, "Immediate",
    R"doc(
    This class represents an immediate operand (i.e. a constant)
    For instance:

    .. code-block:: text

      mov x0, #8;
               |
               +---> Immediate(8)
    )doc"_doc
  );

  obj
    .def_prop_ro("value", &operands::Immediate::value,
      R"doc(The constant value wrapped by this operand)doc"_doc
    )
  ;
}
}
