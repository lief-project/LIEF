#include "LIEF/asm/Instruction.hpp"
#include "asm/pyAssembly.hpp"
#include "enums_wrapper.hpp"
#include "pyErr.hpp"
#include "pyLIEF.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/string_view.h>
#include <nanobind/stl/unique_ptr.h>

#include "nanobind/utils.hpp"

namespace LIEF::assembly::py {
template<>
void create<assembly::Instruction>(nb::module_& m) {
  nb::class_<assembly::Instruction> obj(
      m, "Instruction", "This class represents an assembly instruction"_doc
  );

  obj.attr("__match_args__") = nb::make_tuple("mnemonic");

  enum_<assembly::Instruction::MemoryAccess>(obj, "MemoryAccess", nb::is_flag())
      .value("NONE", Instruction::MemoryAccess::NONE)
      .value("READ", Instruction::MemoryAccess::READ)
      .value("WRITE", Instruction::MemoryAccess::WRITE);

  obj.def_prop_ro("address", &Instruction::address,
                  "Address of the instruction"_doc)

      .def_prop_ro("size", &Instruction::size,
                   "Size of the instruction in bytes"_doc)

      .def_prop_ro("mnemonic", &Instruction::mnemonic,
                   "Instruction mnemonic (e.g. ``br``)"_doc)

      .def(
          "to_string", &Instruction::to_string, "with_address"_a = true,
          "Representation of the current instruction in a pretty assembly way"_doc
      )

      .def_prop_ro(
          "raw", [](const Instruction& inst) { return nb::to_bytes(inst.raw()); },
          "Raw bytes of the current instruction"_doc
      )

      .def_prop_ro("is_call", &Instruction::is_call,
                   "True if the instruction is a call"_doc)

      .def_prop_ro("is_terminator", &Instruction::is_terminator,
                   "True if the instruction marks the end of a basic block"_doc)

      .def_prop_ro("is_branch", &Instruction::is_branch,
                   "True if the instruction is a branch"_doc)

      .def_prop_ro("is_syscall", &Instruction::is_syscall,
                   "True if the instruction is a syscall"_doc)

      .def_prop_ro("is_memory_access", &Instruction::is_memory_access,
                   "True if the instruction performs a memory access"_doc)

      .def_prop_ro("is_move_reg", &Instruction::is_move_reg,
                   "True if the instruction is a register to register move."_doc)

      .def_prop_ro("is_add", &Instruction::is_add,
                   "True if the instruction performs an arithmetic addition."_doc)

      .def_prop_ro("is_trap", &Instruction::is_trap,
                   R"doc(
                   True if the instruction is a trap.

                   - On ``x86/x86-64`` this includes the ``ud1/ud2`` instructions
                   - On ``AArch64`` this includes the ``brk/udf`` instructions
                   )doc"_doc)

      .def_prop_ro("is_barrier", &Instruction::is_barrier,
                   R"doc(
                   True if the instruction prevents executing the instruction
                   that immediately follows the current. This includes return
                   or unconditional branch instructions
                   )doc"_doc)

      .def_prop_ro("is_return", &Instruction::is_return,
                   "True if the instruction is a return"_doc)

      .def_prop_ro("is_indirect_branch", &Instruction::is_indirect_branch,
                   R"doc(
                   True if the instruction is an indirect branch.

                   This includes instructions that branch through a register (e.g.
                   ``jmp rax``, ``br x1``).
                   )doc"_doc)

      .def_prop_ro("is_conditional_branch", &Instruction::is_conditional_branch,
                   R"doc(
                   True if the instruction is **conditionally** jumping to the next
                   instruction **or** an instruction into some other basic block.
                   )doc"_doc)

      .def_prop_ro(
          "is_unconditional_branch", &Instruction::is_unconditional_branch,
          R"doc(
          True if the instruction is jumping (**unconditionally**) to some other
          basic block.
          )doc"_doc
      )

      .def_prop_ro("is_compare", &Instruction::is_compare,
                   "True if the instruction is a comparison"_doc)

      .def_prop_ro("is_move_immediate", &Instruction::is_move_immediate,
                   "True if the instruction is moving an immediate"_doc)

      .def_prop_ro("is_bitcast", &Instruction::is_bitcast,
                   "True if the instruction is doing a bitcast"_doc)

      .def_prop_ro("memory_access", &Instruction::memory_access,
                   "Memory access flags"_doc)

      .def_prop_ro(
          "branch_target",
          [](Instruction& self) {
            return LIEF::py::error_or(&Instruction::branch_target, self);
          },
          R"doc(
          Given a :attr:`~.Instruction.is_branch` instruction, try to evaluate the
          address of the destination.
          )doc"_doc
      )

      .LIEF_DEFAULT_STR(Instruction);
}
}
