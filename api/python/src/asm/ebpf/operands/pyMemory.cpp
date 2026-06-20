#include "asm/ebpf/init.hpp"
#include "LIEF/asm/ebpf/operands/Memory.hpp"

namespace LIEF::assembly::ebpf::py {
template<>
void create<ebpf::operands::Memory>(nb::module_& m) {
  nb::class_<ebpf::operands::Memory, ebpf::Operand> obj(m, "Memory",
    R"doc(
    This class represents a memory operand.

    .. code-block:: text

      *(u64 *)(r1 + 8) = r2
                |    |
                |    +-----> Displacement: 8
                |
                +----------> Base: r1
    )doc"_doc
  );

  obj
    .def_prop_ro("base", &operands::Memory::base,
      R"doc(
      The base register.

      For ``*(u64 *)(r1 + 8)`` it would return ``r1``.
      )doc"_doc
    )
    .def_prop_ro("displacement", &operands::Memory::displacement,
      R"doc(
      The displacement value.

      For ``*(u64 *)(r1 + 8)`` it would return ``8``.
      )doc"_doc
    )
  ;
}
}
