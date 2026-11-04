#include "LIEF/asm/x86/operands/PCRelative.hpp"
#include "asm/x86/init.hpp"

namespace LIEF::assembly::x86::py {
template<>
void create<x86::operands::PCRelative>(nb::module_& m) {
  nb::class_<x86::operands::PCRelative, x86::Operand> obj(
      m, "PCRelative",
      R"doc(
      This class represents a RIP/EIP-relative operand.

      For instance:

      .. code-block:: text

        jmp 67633;
            |
            +----------> PCRelative(67633)
      )doc"_doc
  );

  obj.attr("__match_args__") = nb::make_tuple("value");

  obj.def_prop_ro(
      "value", &x86::operands::PCRelative::value,
      R"doc(
      The effective value that is relative to the current ``rip/eip`` register
      )doc"_doc
  );
}
}
