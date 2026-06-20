#include "asm/mips/init.hpp"
#include "LIEF/asm/mips/operands/Immediate.hpp"

namespace LIEF::assembly::mips::py {
template<>
void create<mips::operands::Immediate>(nb::module_& m) {
  nb::class_<mips::operands::Immediate, mips::Operand> obj(m, "Immediate",
    R"doc(
    This class represents an immediate operand (i.e. a constant)

    For instance:

    .. code-block:: text

      addiu $4, $5, 8
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
