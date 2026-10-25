#include "LIEF/asm/riscv/operands/PCRelative.hpp"
#include "asm/riscv/init.hpp"

namespace LIEF::assembly::riscv::py {
template<>
void create<riscv::operands::PCRelative>(nb::module_& m) {
  nb::class_<riscv::operands::PCRelative, riscv::Operand> obj(
      m, "PCRelative",
      R"doc(
      This class represents a PC-relative operand.

      .. code-block:: text

        auipc a0, 0x1
                  |
                  v
               PC Relative operand
      )doc"_doc
  );

  obj.attr("__match_args__") = nb::make_tuple("value");

  obj.def_prop_ro(
      "value", &riscv::operands::PCRelative::value,
      "The effective value that is relative to the current ``pc`` register"_doc
  );
}
}
