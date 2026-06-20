#include "asm/riscv/init.hpp"
#include "LIEF/asm/riscv/operands/PCRelative.hpp"

namespace LIEF::assembly::riscv::py {
template<>
void create<riscv::operands::PCRelative>(nb::module_& m) {
  nb::class_<riscv::operands::PCRelative, riscv::Operand> obj(m, "PCRelative",
    R"doc(
    This class represents a PC-relative operand.

    .. code-block:: text

      auipc a0, 0x1
                |
                v
             PC Relative operand
    )doc"_doc
  );

  obj
    .def_prop_ro("value", &riscv::operands::PCRelative::value,
      R"doc(
      The effective value that is relative to the current ``pc`` register
      )doc"_doc
    )
  ;
}
}
