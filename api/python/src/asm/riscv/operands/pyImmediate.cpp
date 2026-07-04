#include "asm/riscv/init.hpp"
#include "LIEF/asm/riscv/operands/Immediate.hpp"

namespace LIEF::assembly::riscv::py {
template<>
void create<riscv::operands::Immediate>(nb::module_& m) {
  nb::class_<riscv::operands::Immediate, riscv::Operand> obj(m, "Immediate",
    R"doc(
    This class represents an immediate operand (i.e. a constant)

    For instance:

    .. code-block:: text

      addi a0, a1, 8
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
