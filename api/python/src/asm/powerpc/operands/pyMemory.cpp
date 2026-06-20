#include <nanobind/nanobind.h>

#include "asm/powerpc/init.hpp"
#include "LIEF/asm/powerpc/operands/Memory.hpp"

namespace nanobind::detail {
template<>
struct type_caster<LIEF::assembly::powerpc::operands::Memory::offset_t> {
  NB_TYPE_CASTER(LIEF::assembly::powerpc::operands::Memory::offset_t,
                 const_name("Optional[Union[lief.assembly.powerpc.REG, int]]"));

  bool from_python(handle, uint8_t, cleanup_list *) noexcept {
    return false;
  }

  static handle from_cpp(LIEF::assembly::powerpc::operands::Memory::offset_t val,
                         rv_policy, cleanup_list *) noexcept
  {
    using namespace LIEF::assembly::powerpc;
    using namespace LIEF::assembly::powerpc::operands;
    switch (val.type) {
      case Memory::offset_t::TYPE::REG:
        return make_caster<REG>::from_cpp(val.reg, rv_policy::copy,
                                          /*cleanup_list*/nullptr);

      case Memory::offset_t::TYPE::DISP:
        return make_caster<int64_t>::from_cpp(val.displacement, rv_policy::copy,
                                             /*cleanup_list*/nullptr);
      case Memory::offset_t::TYPE::NONE:
        return nb::none();
    }
    return nb::none();
  }
};
}


namespace LIEF::assembly::powerpc::py {
template<>
void create<powerpc::operands::Memory>(nb::module_& m) {
  nb::class_<powerpc::operands::Memory, powerpc::Operand> obj(m, "Memory",
    R"doc(
    This class represents a memory operand.

    .. code-block:: text

      lwz   3, 8(4)              lwzx   3, 4, 5
             |  |                       |  |  |
      +------+  +---+            +------+   |  +---+
      |             |           |          |      |
      v             v           v          v      v
      Disp         Base        Reg        Base   Index
    )doc"_doc
  );

  obj
    .def_prop_ro("base", &operands::Memory::base,
      R"doc(
      The base register.

      For ``lwz 3, 8(4)`` it would return ``4``.
      )doc"_doc
    )
    .def_prop_ro("offset", &operands::Memory::offset,
      R"doc(
      The addressing offset.

      It can be either:

      - An index register (e.g. ``lwzx 3, 4, 5``)
      - A displacement (e.g. ``lwz 3, 8(4)``)
      )doc"_doc
    )
  ;
}
}
