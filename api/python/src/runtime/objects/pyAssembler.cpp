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
#include <nanobind/stl/string_view.h>

#include "LIEF/runtime/assembler.hpp"
#include "LIEF/asm/AssemblerConfig.hpp"
#include "pyLIEF.hpp"
#include "nanobind/utils.hpp"

namespace LIEF::runtime::py {
void init_assembler(nb::module_& m) {
  m.def("assemble",
    [] (uint64_t address, std::string_view Asm,
        assembly::AssemblerConfig& config)
    {
      return nb::to_bytes(runtime::assemble(address, Asm, config));
    }, "address"_a, "assembly"_a,
    "config"_a = assembly::AssemblerConfig::default_config(),
    R"doc(
    Assemble the provided assembly code at the specified (absolute) virtual
    address.

    The function returns the generated assembly bytes.

    .. code-block:: python

      from lief import runtime
      code = runtime.assemble(0x7f0011223344, """
      xor rax, rbx;
      mov rcx, rax;
      """)

    If you need to configure the assembly engine or to define addresses for
    symbols, you can provide your own :class:`~.assembly.AssemblerConfig` instance.
    )doc"_doc);
}
}
