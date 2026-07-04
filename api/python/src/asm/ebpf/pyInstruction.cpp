#include "LIEF/asm/ebpf/Instruction.hpp"
#include "LIEF/asm/ebpf/Operand.hpp"
#include "pyOwningIterator.hpp"

#include <nanobind/make_iterator.h>

#include "asm/ebpf/init.hpp"

#include <nanobind/stl/unique_ptr.h>

namespace LIEF::assembly::ebpf::py {
template<>
void create<ebpf::Instruction>(nb::module_& m) {
  nb::class_<ebpf::Instruction, assembly::Instruction> obj(m, "Instruction",
    R"doc(This class represents an eBPF instruction)doc"_doc
  );

  obj
    .def_prop_ro("opcode", &Instruction::opcode,
      R"doc(The instruction opcode as defined in LLVM)doc"_doc
    )
    .def_prop_ro("operands", [] (const ebpf::Instruction& self) {
        auto ops = LIEF::py::owning_range(self.operands());
        return nb::make_iterator<nb::rv_policy::reference_internal>(
          nb::type<ebpf::Instruction>(), "operands_it", ops
        );
      }, nb::keep_alive<0, 1>(),
      R"doc(Iterator over the operands of the current instruction)doc"_doc
    )
  ;
}
}
