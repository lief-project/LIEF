#include "asm/x86/init.hpp"
#include "LIEF/asm/x86/operands/Memory.hpp"

namespace LIEF::assembly::x86::py {
template<>
void create<x86::operands::Memory>(nb::module_& m) {
  nb::class_<x86::operands::Memory, x86::Operand> obj(m, "Memory",
    R"doc(
    This class represents a memory operand.

    For instance:

    .. code-block:: text

      movq xmm3, qword ptr [rip + 823864];

                           |
                           |
                         Memory
                           |
               +-----------+-----------+
               |           |           |
           Base: rip    Scale: 1    Displacement: 823864
    )doc"_doc
  );

  obj
    .def_prop_ro("base", &x86::operands::Memory::base,
      R"doc(
      The base register.

      For ``lea rdx, [rip + 244634]`` it would return ``rip``
      )doc"_doc
    )

    .def_prop_ro("scaled_register", &x86::operands::Memory::scaled_register,
      R"doc(
      The scaled register.

      For ``mov rdi, qword ptr [r13 + 8*r14]`` it would return ``r14``
      )doc"_doc
    )

    .def_prop_ro("segment_register", &x86::operands::Memory::segment_register,
      R"doc(
      The segment register associated with the memory operation.

      For ``mov eax, dword ptr gs:[0]`` is would return ``gs``
      )doc"_doc
    )

    .def_prop_ro("scale", &x86::operands::Memory::scale,
      R"doc(
      The scale value associated with the :attr:`~.scaled_register`:

      For ``mov rdi, qword ptr [r13 + 8*r14]`` it would return ``8``
      )doc"_doc
    )

    .def_prop_ro("displacement", &x86::operands::Memory::displacement,
      R"doc(
      The displacement value.

      For ``call qword ptr [rip + 248779]`` it would return ``248779``
      )doc"_doc
    )
  ;
}
}
