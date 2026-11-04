#include "LIEF/asm/mips/operands/Immediate.hpp"
#include "asm/mips/init.hpp"

namespace LIEF::assembly::mips::py {
template<>
void create<mips::operands::Immediate>(nb::module_& m) {
  nb::class_<mips::operands::Immediate, mips::Operand> obj(
      m, "Immediate",
      R"doc(
      This class represents an immediate operand (i.e. a constant)

      For instance:

      .. code-block:: text

        addiu $4, $5, 8
                      |
                      +---> Immediate(8)
      )doc"_doc
  );

  obj.attr("__match_args__") = nb::make_tuple("value");

  obj.def_prop_ro("value", &operands::Immediate::value,
                  "The constant value wrapped by this operand"_doc);
}
}
