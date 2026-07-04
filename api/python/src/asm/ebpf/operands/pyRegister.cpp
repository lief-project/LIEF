#include "asm/ebpf/init.hpp"
#include "LIEF/asm/ebpf/operands/Register.hpp"

namespace LIEF::assembly::ebpf::py {
template<>
void create<ebpf::operands::Register>(nb::module_& m) {
  nb::class_<ebpf::operands::Register, ebpf::Operand> obj(m, "Register",
    R"doc(
    This class represents a register operand.

    For instance:

    .. code-block:: text

      r0 = r1
       |    |
       |    +---------> Register(r1)
       |
       +--------------> Register(r0)
    )doc"_doc
  );

  obj
    .def_prop_ro("value", &ebpf::operands::Register::value,
      R"doc(
      The effective :class:`lief.assembly.ebpf.REG` wrapped by this operand
      )doc"_doc
    )
  ;
}
}
