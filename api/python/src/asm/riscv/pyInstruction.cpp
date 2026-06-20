#include "LIEF/asm/riscv/Instruction.hpp"
#include "LIEF/asm/riscv/Operand.hpp"
#include "pyOwningIterator.hpp"

#include <nanobind/make_iterator.h>

#include "asm/riscv/init.hpp"

#include <nanobind/stl/unique_ptr.h>

namespace LIEF::assembly::riscv::py {
template<>
void create<riscv::Instruction>(nb::module_& m) {
  nb::class_<riscv::Instruction, assembly::Instruction> obj(m, "Instruction",
    R"doc(This class represents a RISC-V (32 or 64 bit) instruction)doc"_doc
  );

  obj
    .def_prop_ro("opcode", &Instruction::opcode,
      R"doc(The instruction opcode as defined in LLVM)doc"_doc
    )
    .def_prop_ro("operands", [] (const riscv::Instruction& self) {
        auto ops = LIEF::py::owning_range(self.operands());
        return nb::make_iterator<nb::rv_policy::reference_internal>(
          nb::type<riscv::Instruction>(), "operands_it", ops
        );
      }, nb::keep_alive<0, 1>(),
      R"doc(Iterator over the operands of the current instruction)doc"_doc
    )
  ;
}
}
