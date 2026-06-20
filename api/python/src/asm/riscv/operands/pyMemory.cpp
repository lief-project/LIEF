#include "asm/riscv/init.hpp"
#include "LIEF/asm/riscv/operands/Memory.hpp"

namespace LIEF::assembly::riscv::py {
template<>
void create<riscv::operands::Memory>(nb::module_& m) {
  nb::class_<riscv::operands::Memory, riscv::Operand> obj(m, "Memory",
    R"doc(
    This class represents a memory operand.

    .. code-block:: text

      lw   a0, 8(sp)
               |  |
               |  +----> Base: sp
               |
               +-------> Displacement: 8
    )doc"_doc
  );

  obj
    .def_prop_ro("base", &operands::Memory::base,
      R"doc(
      The base register.

      For ``lw a0, 8(sp)`` it would return ``sp``.
      )doc"_doc
    )
    .def_prop_ro("displacement", &operands::Memory::displacement,
      R"doc(
      The displacement value.

      For ``lw a0, 8(sp)`` it would return ``8``.
      )doc"_doc
    )
  ;
}
}
