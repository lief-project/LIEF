#include "asm/mips/init.hpp"
#include "LIEF/asm/mips/operands/Register.hpp"

namespace LIEF::assembly::mips::py {
template<>
void create<mips::operands::Register>(nb::module_& m) {
  nb::class_<mips::operands::Register, mips::Operand> obj(m, "Register",
    R"doc(
    This class represents a register operand.

    For instance:

    .. code-block:: text

      move $4, $5
            |   |
            |   +---------> Register($5)
            |
            +-------------> Register($4)
    )doc"_doc
  );

  obj
    .def_prop_ro("value", &mips::operands::Register::value,
      R"doc(
      The effective :class:`lief.assembly.mips.REG` wrapped by this operand
      )doc"_doc
    )
  ;
}
}
