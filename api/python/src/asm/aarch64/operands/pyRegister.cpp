#include <nanobind/nanobind.h>

#include "asm/aarch64/init.hpp"
#include "LIEF/asm/aarch64/operands/Register.hpp"

namespace nanobind::detail {
template<>
struct type_caster<LIEF::assembly::aarch64::operands::Register::reg_t> {
  NB_TYPE_CASTER(LIEF::assembly::aarch64::operands::Register::reg_t,
                 const_name("Optional[Union[lief.assembly.aarch64.REG, lief.assembly.aarch64.SYSREG]]"));

  bool from_python(handle src, uint8_t, cleanup_list *) noexcept {
    return false;
  }

  static handle from_cpp(LIEF::assembly::aarch64::operands::Register::reg_t val,
                         rv_policy, cleanup_list *) noexcept
  {
    using namespace LIEF::assembly::aarch64;
    using namespace LIEF::assembly::aarch64::operands;
    switch (val.type) {
      case Register::reg_t::TYPE::REG:
        return make_caster<REG>::from_cpp(val.reg, rv_policy::copy,
                                          /*cleanup_list*/nullptr);

      case Register::reg_t::TYPE::SYSREG:
        return make_caster<SYSREG>::from_cpp(val.sysreg, rv_policy::copy,
                                             /*cleanup_list*/nullptr);
      case Register::reg_t::TYPE::NONE:
        return nb::none();
    }
    return nb::none();
  }
};
}

namespace LIEF::assembly::aarch64::py {
template<>
void create<aarch64::operands::Register>(nb::module_& m) {
  nb::class_<aarch64::operands::Register, aarch64::Operand> obj(m, "Register",
    R"doc(
    This class represents a register operand.

    .. code-block:: text

      mrs     x0, TPIDR_EL0
              |   |
       +------+   +-------+
       |                  |
       v                  v
       REG              SYSREG
    )doc"_doc
  );

  obj
    .def_prop_ro("value", &operands::Register::value,
      R"doc(
      The effective register as either: a :class:`lief.assembly.aarch64.REG` or
      a :class:`lief.assembly.aarch64.SYSREG`.
      )doc"_doc
    )
  ;


}
}
