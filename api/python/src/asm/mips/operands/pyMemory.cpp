#include <nanobind/nanobind.h>

#include "asm/mips/init.hpp"
#include "LIEF/asm/mips/operands/Memory.hpp"

namespace nanobind::detail {
template<>
struct type_caster<LIEF::assembly::mips::operands::Memory::offset_t> {
  NB_TYPE_CASTER(LIEF::assembly::mips::operands::Memory::offset_t,
                 const_name("Optional[Union[lief.assembly.mips.REG, int]]"));

  bool from_python(handle, uint8_t, cleanup_list *) noexcept {
    return false;
  }

  static handle from_cpp(LIEF::assembly::mips::operands::Memory::offset_t val,
                         rv_policy, cleanup_list *) noexcept
  {
    using namespace LIEF::assembly::mips;
    using namespace LIEF::assembly::mips::operands;
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


namespace LIEF::assembly::mips::py {
template<>
void create<mips::operands::Memory>(nb::module_& m) {
  nb::class_<mips::operands::Memory, mips::Operand> obj(m, "Memory",
    R"doc(
    This class represents a memory operand.

    .. code-block:: text

      lw    $4, 8($5)            ldxc1  $f2, $4($7)
             |  | |                      |   |  |
      +------+  | +---+          +-------+   |  +-----+
      |         |     |          |           |        |
      v         v     v          v           v        v
      Reg      Disp  Base       Reg         Index    Base
    )doc"_doc
  );

  obj
    .def_prop_ro("base", &operands::Memory::base,
      R"doc(
      The base register.

      For ``lw $4, 8($5)`` it would return ``$5``.
      )doc"_doc
    )
    .def_prop_ro("offset", &operands::Memory::offset,
      R"doc(
      The addressing offset.

      It can be either:

      - A register (e.g. ``ldxc1 $f2, $4($7)``)
      - A displacement (e.g. ``lw $4, 8($5)``)
      )doc"_doc
    )
  ;
}
}
