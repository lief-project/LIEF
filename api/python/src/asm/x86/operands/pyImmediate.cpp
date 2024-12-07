#include "asm/x86/init.hpp"
#include "LIEF/asm/x86/operands/Immediate.hpp"

namespace LIEF::assembly::x86::py {
template<>
void create<x86::operands::Immediate>(nb::module_& m) {
  nb::class_<x86::operands::Immediate, x86::Operand> obj(m, "Immediate",
    R"doc(
    This class represents an immediate operand (i.e. a constant)

    For instance:

    .. code-block:: text

      mov edi, 1;
               |
               +---> Immediate(1)
    )doc"_doc
  );

  obj
    .def_prop_ro("value", &operands::Immediate::value,
      R"doc(The constant value wrapped by this operand)doc"_doc
    )
  ;
}
}
