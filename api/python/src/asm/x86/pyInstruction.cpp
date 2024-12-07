#include "LIEF/asm/x86/Instruction.hpp"
#include "LIEF/asm/x86/Operand.hpp"

#include "asm/x86/init.hpp"

#include <nanobind/make_iterator.h>

#include <nanobind/stl/unique_ptr.h>

namespace LIEF::assembly::x86::py {
template<>
void create<x86::Instruction>(nb::module_& m) {
  nb::class_<x86::Instruction, assembly::Instruction> obj(m, "Instruction",
    R"doc(This class represents a x86/x86-64 instruction)doc"_doc
  );

  obj
    .def_prop_ro("operands", [] (const x86::Instruction& self) {
        auto ops = self.operands();
        return nb::make_iterator<nb::rv_policy::reference_internal>(
          nb::type<x86::Instruction>(), "operands_it", ops
        );
      }, nb::keep_alive<0, 1>(),
      R"doc(Iterator over the operands of the current instruction)doc"_doc
    )
    .def_prop_ro("opcode", &Instruction::opcode,
      R"doc(The instruction opcode as defined in LLVM)doc"_doc
    )
  ;
}
}
