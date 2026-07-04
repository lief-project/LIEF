#include <nanobind/nanobind.h>

#include "asm/riscv/init.hpp"
#include "LIEF/asm/riscv/operands/Register.hpp"

namespace nanobind::detail {
template<>
struct type_caster<LIEF::assembly::riscv::operands::Register::reg_t> {
  NB_TYPE_CASTER(LIEF::assembly::riscv::operands::Register::reg_t,
                 const_name("Optional[Union[lief.assembly.riscv.REG, lief.assembly.riscv.SYSREG]]"));

  bool from_python(handle, uint8_t, cleanup_list *) noexcept {
    return false;
  }

  static handle from_cpp(LIEF::assembly::riscv::operands::Register::reg_t val,
                         rv_policy, cleanup_list *) noexcept
  {
    using namespace LIEF::assembly::riscv;
    using namespace LIEF::assembly::riscv::operands;
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

namespace LIEF::assembly::riscv::py {
template<>
void create<riscv::operands::Register>(nb::module_& m) {
  nb::class_<riscv::operands::Register, riscv::Operand> obj(m, "Register",
    R"doc(
    This class represents a register operand.

    .. code-block:: text

      csrr    a0, mstatus
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
      The effective register as either: a :class:`lief.assembly.riscv.REG` or
      a :class:`lief.assembly.riscv.SYSREG`.
      )doc"_doc
    )
  ;


}
}
