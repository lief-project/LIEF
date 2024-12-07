#include "LIEF/asm/aarch64/Instruction.hpp"
#include "LIEF/asm/aarch64/Operand.hpp"

#include <nanobind/make_iterator.h>

#include "asm/aarch64/init.hpp"

#include <nanobind/stl/unique_ptr.h>

namespace LIEF::assembly::aarch64::py {
template<>
void create<aarch64::Instruction>(nb::module_& m) {
  nb::class_<aarch64::Instruction, assembly::Instruction> obj(m, "Instruction",
    R"doc(
    This class represents an AArch64 instruction
    )doc"_doc
  );

  obj
    .def_prop_ro("opcode", &Instruction::opcode,
      R"doc(The instruction opcode as defined in LLVM)doc"_doc
    )
    .def_prop_ro("operands", [] (const aarch64::Instruction& self) {
        auto ops = self.operands();
        return nb::make_iterator<nb::rv_policy::reference_internal>(
          nb::type<aarch64::Instruction>(), "operands_it", ops
        );
      }, nb::keep_alive<0, 1>(),
      R"doc(Iterator over the operands of the current instruction)doc"_doc
    )
  ;
}
}
