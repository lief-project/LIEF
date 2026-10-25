#include "LIEF/asm/mips/operands/PCRelative.hpp"
#include "asm/mips/init.hpp"

namespace LIEF::assembly::mips::py {
template<>
void create<mips::operands::PCRelative>(nb::module_& m) {
  nb::class_<mips::operands::PCRelative, mips::Operand> obj(
      m, "PCRelative",
      R"doc(
      This class represents a PC-relative operand.

      .. code-block:: text

        bal 0x100
            |
            v
         PC Relative operand
      )doc"_doc
  );

  obj.attr("__match_args__") = nb::make_tuple("value");

  obj.def_prop_ro(
      "value", &mips::operands::PCRelative::value,
      "The effective value that is relative to the current ``pc`` register"_doc
  );
}
}
