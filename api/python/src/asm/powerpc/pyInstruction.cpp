#include "LIEF/asm/powerpc/Instruction.hpp"
#include "LIEF/asm/powerpc/Operand.hpp"
#include "pyOwningIterator.hpp"

#include <nanobind/make_iterator.h>

#include "asm/powerpc/init.hpp"

#include <nanobind/stl/unique_ptr.h>

namespace LIEF::assembly::powerpc::py {
template<>
void create<powerpc::Instruction>(nb::module_& m) {
  nb::class_<powerpc::Instruction, assembly::Instruction> obj(m, "Instruction",
    R"doc(This class represents a PowerPC (ppc64/ppc32) instruction)doc"_doc
  );

  obj
    .def_prop_ro("opcode", &Instruction::opcode,
      R"doc(The instruction opcode as defined in LLVM)doc"_doc
    )
    .def_prop_ro("operands", [] (const powerpc::Instruction& self) {
        auto ops = LIEF::py::owning_range(self.operands());
        return nb::make_iterator<nb::rv_policy::reference_internal>(
          nb::type<powerpc::Instruction>(), "operands_it", ops
        );
      }, nb::keep_alive<0, 1>(),
      R"doc(Iterator over the operands of the current instruction)doc"_doc
    )
  ;
}
}
