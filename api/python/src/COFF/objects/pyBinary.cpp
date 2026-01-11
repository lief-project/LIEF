/* Copyright 2025 - 2026 R. Thomas
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

#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/unique_ptr.h>

#include "COFF/pyCOFF.hpp"
#include "LIEF/COFF/Binary.hpp"
#include "LIEF/COFF/Relocation.hpp"
#include "LIEF/COFF/Symbol.hpp"
#include "LIEF/COFF/Section.hpp"
#include "LIEF/COFF/String.hpp"

#include "LIEF/asm/Engine.hpp"
#include "LIEF/asm/Instruction.hpp"

#include <sstream>

#include <nanobind/stl/string.h>

#include "pyIterator.hpp"

namespace LIEF::COFF::py {

template<>
void create<Binary>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<Binary> bin(m, "Binary",
    "Class that represents a COFF Binary"_doc);

  struct it_symbols : public Binary::it_symbols {
    using Binary::it_symbols::it_symbols;
  };

  struct it_strings_table : public Binary::it_strings_table {
    using Binary::it_strings_table::it_strings_table;
  };

  init_ref_iterator<Binary::it_sections>(bin, "it_section");
  init_ref_iterator<Binary::it_relocations>(bin, "it_relocations");
  init_ref_iterator<it_symbols>(bin, "it_symbols");
  init_ref_iterator<it_strings_table>(bin, "it_strings_table");
  init_ref_iterator<Binary::it_functions>(bin, "it_functions");

  bin
    .def_prop_ro("header", nb::overload_cast<>(&Binary::header),
      "The COFF header"_doc
    )
    .def_prop_ro("sections",
      nb::overload_cast<>(&Binary::sections),
      "Iterator over the different sections located in this COFF binary"_doc,
      nb::keep_alive<0, 1>()
    )

    .def_prop_ro("relocations",
      nb::overload_cast<>(&Binary::relocations),
      "Iterator over **all** the relocations used by this COFF binary"_doc,
      nb::keep_alive<0, 1>()
    )

    .def_prop_ro("symbols",
      nb::overload_cast<>(&Binary::symbols),
      "Iterator over the COFF's symbols"_doc,
      nb::keep_alive<0, 1>()
    )

    .def_prop_ro("functions",
        nb::overload_cast<>(&Binary::functions),
        "Iterator over the functions implemented in this COFF",
        nb::keep_alive<0, 1>())

    .def_prop_ro("string_table",
      nb::overload_cast<>(&Binary::string_table),
      "Iterator over the COFF's strings"_doc,
      nb::keep_alive<0, 1>()
    )

    .def("find_string", nb::overload_cast<uint32_t>(&Binary::find_string),
        R"doc(
        Try to find the COFF string at the given offset in the COFF string table.

        .. warning::

            This offset must include the first 4 bytes holding the size of
            the table. Hence, the first string starts a the offset 4.
        )doc"_doc, "offset"_a,
        nb::rv_policy::reference_internal)

    .def("find_function",
         nb::overload_cast<const std::string&>(&Binary::find_function),
         "Try to find the function (symbol) with the given name"_doc,
         "name"_a, nb::rv_policy::reference_internal
      )

    .def("find_demangled_function",
         nb::overload_cast<const std::string&>(&Binary::find_demangled_function),
         "Try to find the function (symbol) with the given **demangled** name"_doc,
         "name"_a, nb::rv_policy::reference_internal
      )


    .def("disassemble", [] (const Binary& self, const Symbol& function) {
          auto insts = self.disassemble(function);
          return nb::make_iterator<nb::rv_policy::reference_internal>(
              nb::type<Binary>(), "instructions_it", insts);
      }, "function"_a, nb::keep_alive<0, 1>(),
      R"doc(
      Disassemble code for the given symbol

      .. code-block:: python

        func = binary.find_demangled_function("int __cdecl my_function(int, int)");
        insts = binary.disassemble("main");
        for inst in insts:
            print(inst)

      .. seealso:: :class:`lief.assembly.Instruction`
      )doc"_doc)

    .def("disassemble", [] (const Binary& self, const std::string& function) {
          auto insts = self.disassemble(function);
          return nb::make_iterator<nb::rv_policy::reference_internal>(
              nb::type<Binary>(), "instructions_it", insts);
      }, "function_name"_a, nb::keep_alive<0, 1>(),
      R"doc(
      Disassemble code for the given symbol name

      .. code-block:: python

        insts = binary.disassemble("main");
        for inst in insts:
            print(inst)

      .. seealso:: :class:`lief.assembly.Instruction`
      )doc"_doc
    )

    .def("disassemble_from_bytes",
         [] (const Binary& self, const nb::bytes& buffer, uint64_t address) {
          auto insts = self.disassemble(
            reinterpret_cast<const uint8_t*>(buffer.c_str()),
            buffer.size(), address
          );
          return nb::make_iterator<nb::rv_policy::reference_internal>(
              nb::type<Binary>(), "instructions_it", insts);
      }, "buffer"_a, "address"_a = 0, nb::keep_alive<0, 1>(), nb::keep_alive<0, 2>(),
      R"doc(
      Disassemble code from the provided bytes

      .. code-block:: python

        raw = bytes(binary.get_section(".text").content)
        insts = binary.disassemble_from_bytes(raw);
        for inst in insts:
            print(inst)

      .. seealso:: :class:`lief.assembly.Instruction`
      )doc"_doc
    )
  LIEF_DEFAULT_STR(Binary);

}

}
