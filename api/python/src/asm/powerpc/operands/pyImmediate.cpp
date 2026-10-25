#include "LIEF/asm/powerpc/operands/Immediate.hpp"
#include "asm/powerpc/init.hpp"

namespace LIEF::assembly::powerpc::py {
template<>
void create<powerpc::operands::Immediate>(nb::module_& m) {
  nb::class_<powerpc::operands::Immediate, powerpc::Operand> obj(
      m, "Immediate",
      R"doc(
      This class represents an immediate operand (i.e. a constant)

      For instance:

      .. code-block:: text

        li 3, 8
              |
              +---> Immediate(8)
      )doc"_doc
  );

  obj.attr("__match_args__") = nb::make_tuple("value");

  obj.def_prop_ro("value", &operands::Immediate::value,
                  "The constant value wrapped by this operand"_doc);
}
}
