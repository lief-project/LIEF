#include "LIEF/asm/aarch64/operands/Immediate.hpp"
#include "asm/aarch64/init.hpp"

namespace LIEF::assembly::aarch64::py {
template<>
void create<aarch64::operands::Immediate>(nb::module_& m) {
  nb::class_<aarch64::operands::Immediate, aarch64::Operand> obj(
      m, "Immediate",
      R"doc(
      This class represents an immediate operand (i.e. a constant)
      For instance:

      .. code-block:: text

        mov x0, #8;
                 |
                 +---> Immediate(8)
      )doc"_doc
  );

  obj.attr("__match_args__") = nb::make_tuple("value");

  obj.def_prop_ro("value", &operands::Immediate::value,
                  "The constant value wrapped by this operand"_doc);
}
}
