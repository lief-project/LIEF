#include <nanobind/nanobind.h>

#include "asm/aarch64/init.hpp"
#include "LIEF/asm/aarch64/operands/Memory.hpp"

namespace nanobind::detail {
template<>
struct type_caster<LIEF::assembly::aarch64::operands::Memory::offset_t> {
  NB_TYPE_CASTER(LIEF::assembly::aarch64::operands::Memory::offset_t,
                 const_name("Optional[Union[lief.assembly.aarch64.REG, int]]"));

  bool from_python(handle src, uint8_t, cleanup_list *) noexcept {
    return false;
  }

  static handle from_cpp(LIEF::assembly::aarch64::operands::Memory::offset_t val,
                         rv_policy, cleanup_list *) noexcept
  {
    using namespace LIEF::assembly::aarch64;
    using namespace LIEF::assembly::aarch64::operands;
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


namespace LIEF::assembly::aarch64::py {
template<>
void create<aarch64::operands::Memory>(nb::module_& m) {
  nb::class_<aarch64::operands::Memory, aarch64::Operand> obj(m, "Memory",
    R"doc(
    This class represents a memory operand.

    .. code-block:: text

      ldr     x0, [x1, x2, lsl #3]
                   |   |    |
      +------------+   |    +--------+
      |                |             |
      v                v             v
      Base            Reg Offset    Shift
    )doc"_doc
  );

  nb::enum_<operands::Memory::SHIFT>(obj, "SHIFT")
    .value("UNKNOWN", operands::Memory::SHIFT::UNKNOWN)
    .value("LSL", operands::Memory::SHIFT::LSL)
    .value("UXTX", operands::Memory::SHIFT::UXTX)
    .value("UXTW", operands::Memory::SHIFT::UXTW)
    .value("SXTX", operands::Memory::SHIFT::SXTX)
    .value("SXTW", operands::Memory::SHIFT::SXTW)
  ;

  nb::class_<operands::Memory::shift_info_t>(obj, "shift_info_t",
    R"doc(This structure holds shift info (type + value))doc"_doc
  )
    .def_ro("type", &operands::Memory::shift_info_t::type)
    .def_ro("value", &operands::Memory::shift_info_t::value)
  ;

  obj
    .def_prop_ro("base", &operands::Memory::base,
      R"doc(
      The base register.

      For ``str x3, [x8, #8]`` it would return ``x8``.
      )doc"_doc
    )
    .def_prop_ro("offset", &operands::Memory::offset,
      R"doc(
      The addressing offset.

      It can be either:

      - A register (e.g. ``ldr x0, [x1, x3]``)
      - An offset (e.g. ``ldr x0, [x1, #8]``)
      )doc"_doc
    )
    .def_prop_ro("shift", &operands::Memory::shift,
      R"doc(
      Shift information.

      For instance, for ``ldr x1, [x2, x3, lsl #3]`` it would
      return a :attr:`~.Memory.SHIFT.LSL` with a :attr:`~.Memory.shift_info_t.value`
      set to ``3``.
      )doc"_doc
    )
  ;
}
}
