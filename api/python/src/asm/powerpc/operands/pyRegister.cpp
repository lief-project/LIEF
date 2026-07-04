#include "asm/powerpc/init.hpp"
#include "LIEF/asm/powerpc/operands/Register.hpp"

namespace LIEF::assembly::powerpc::py {
template<>
void create<powerpc::operands::Register>(nb::module_& m) {
  nb::class_<powerpc::operands::Register, powerpc::Operand> obj(m, "Register",
    R"doc(
    This class represents a register operand.

    For instance:

    .. code-block:: text

      add 3, 4, 5
           |  |  |
           |  |  +---------> Register(5)
           |  +------------> Register(4)
           +---------------> Register(3)
    )doc"_doc
  );

  obj
    .def_prop_ro("value", &powerpc::operands::Register::value,
      R"doc(
      The effective :class:`lief.assembly.powerpc.REG` wrapped by this operand
      )doc"_doc
    )
  ;
}
}
