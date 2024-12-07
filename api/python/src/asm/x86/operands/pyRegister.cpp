#include "asm/x86/init.hpp"
#include "LIEF/asm/x86/operands/Register.hpp"

namespace LIEF::assembly::x86::py {
template<>
void create<x86::operands::Register>(nb::module_& m) {
  nb::class_<x86::operands::Register, x86::Operand> obj(m, "Register",
    R"doc(
    This class represents a register operand.

    For instance:

    .. code-block:: text

      mov r15d, edi
           |     |
           |     +---------> Register(EDI)
           |
           +---------------> Register(R15D)
    )doc"_doc
  );

  obj
    .def_prop_ro("value", &x86::operands::Register::value,
      R"doc(
      The effective :class:`lief.assembly.x86.REG` wrapped by this operand
      )doc"_doc
    )
  ;
}
}
