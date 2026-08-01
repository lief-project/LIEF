#include "LIEF/asm/x86/Instruction.hpp"
#include "LIEF/asm/x86/Operand.hpp"

#include "asm/x86/init.hpp"
#include "pyOwningIterator.hpp"

#include <nanobind/make_iterator.h>

#include <nanobind/stl/unique_ptr.h>

namespace LIEF::assembly::x86::py {
template<>
void create<x86::Instruction>(nb::module_& m) {
  nb::class_<x86::Instruction, assembly::Instruction> obj(m, "Instruction",
    R"doc(This class represents a x86/x86-64 instruction)doc"_doc
  );

  obj.attr("__match_args__") = nb::make_tuple("opcode", "operands");

  obj
    .def_prop_ro("operands", [] (const x86::Instruction& self) {
        auto ops = LIEF::py::owning_range(self.operands());
        return nb::make_iterator<nb::rv_policy::reference_internal>(
          nb::type<x86::Instruction>(), "operands_it", ops
        );
      }, nb::keep_alive<0, 1>(),
      R"doc(Iterator over the operands of the current instruction)doc"_doc
    )
    .def_prop_ro("opcode", &Instruction::opcode,
      R"doc(The instruction opcode as defined in LLVM)doc"_doc
    )
    .def_prop_ro("has_lock_prefix", &Instruction::has_lock_prefix,
      R"doc(True if this instruction has a ``LOCK`` prefix)doc"_doc
    )
    .def_prop_ro("is_lockable", &Instruction::is_lockable,
      R"doc(True if the ``LOCK`` prefix is architecturally valid on this instruction)doc"_doc
    )
    .def_prop_ro("is_atomic", &Instruction::is_atomic,
      R"doc(True if this instruction executes as an atomic read-modify-write)doc"_doc
    )
    .def("lock", &Instruction::lock,
      R"doc(
      Re-encoded copy of this instruction with a ``LOCK`` prefix added.

      If the instruction already has a ``LOCK`` prefix, it returns a plain copy.
      )doc"_doc
    )
    .def("unlock", &Instruction::unlock,
      R"doc(
      Re-encoded copy of this instruction with the ``LOCK`` prefix removed.

      If the instruction does not have a ``LOCK`` prefix, it returns a plain
      copy or ``None`` if the ``LOCK`` semantic can't be removed.
      )doc"_doc
    )
  ;
}
}
