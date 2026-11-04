/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "LIEF/asm/Instruction.hpp"
#include "LIEF/runtime/disassembler.hpp"
#include "pyLIEF.hpp"

#include <nanobind/make_iterator.h>
#include <nanobind/stl/unique_ptr.h>

#include "pyOwningIterator.hpp"

namespace LIEF::runtime::py {
void init_disassembler(nb::module_& m) {
  m.def(
      "disassemble",
      [](uintptr_t addr) {
        auto insts = LIEF::py::owning_range(runtime::disassemble(addr));
        return nb::make_iterator<nb::rv_policy::take_ownership>(
            nb::type<assembly::Instruction>(), "instructions_it", insts
        );
      },
      "addr"_a,
      R"doc(
      Start disassembling instructions at the given **absolute** virtual address.

      .. code-block:: python

        from lief import runtime
        for inst in runtime.disassemble(0x7f0011223344):
            print(inst)

      .. seealso:: :class:`lief.assembly.Instruction`
      )doc"_doc
  );
}
}
