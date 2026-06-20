#include "LIEF/asm/mips/Instruction.hpp"
#include "LIEF/asm/mips/Operand.hpp"
#include "pyOwningIterator.hpp"

#include <nanobind/make_iterator.h>

#include "asm/mips/init.hpp"

#include <nanobind/stl/unique_ptr.h>

namespace LIEF::assembly::mips::py {
template<>
void create<mips::Instruction>(nb::module_& m) {
  nb::class_<mips::Instruction, assembly::Instruction> obj(m, "Instruction",
    R"doc(This class represents a Mips instruction (including mips64, mips32))doc"_doc
  );

  obj
    .def_prop_ro("opcode", &Instruction::opcode,
      R"doc(The instruction opcode as defined in LLVM)doc"_doc
    )
    .def_prop_ro("operands", [] (const mips::Instruction& self) {
        auto ops = LIEF::py::owning_range(self.operands());
        return nb::make_iterator<nb::rv_policy::reference_internal>(
          nb::type<mips::Instruction>(), "operands_it", ops
        );
      }, nb::keep_alive<0, 1>(),
      R"doc(Iterator over the operands of the current instruction)doc"_doc
    )
  ;
}
}
