#include "LIEF/asm/ebpf/operands/Immediate.hpp"
#include "asm/ebpf/init.hpp"

namespace LIEF::assembly::ebpf::py {
template<>
void create<ebpf::operands::Immediate>(nb::module_& m) {
  nb::class_<ebpf::operands::Immediate, ebpf::Operand> obj(
      m, "Immediate",
      R"doc(
      This class represents an immediate operand (i.e. a constant)

      For instance:

      .. code-block:: text

        r1 = 8
             |
             +---> Immediate(8)
      )doc"_doc
  );

  obj.attr("__match_args__") = nb::make_tuple("value");

  obj.def_prop_ro("value", &operands::Immediate::value,
                  "The constant value wrapped by this operand"_doc);
}
}
