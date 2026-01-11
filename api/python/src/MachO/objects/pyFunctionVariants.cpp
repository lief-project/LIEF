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
#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include "LIEF/MachO/FunctionVariants.hpp"
#include "pyIterator.hpp"

#include "MachO/pyMachO.hpp"
#include "nanobind/extra/stl/lief_span.h"

namespace LIEF::MachO::py {

using RuntimeTableEntry = FunctionVariants::RuntimeTableEntry;
using RuntimeTable = FunctionVariants::RuntimeTable;
using FLAGS = FunctionVariants::RuntimeTableEntry::FLAGS;
using KIND = FunctionVariants::RuntimeTable::KIND;

template<>
void create<FunctionVariants>(nb::module_& m) {
  using namespace LIEF::py;
  nb::class_<FunctionVariants, LoadCommand> cmd(m, "FunctionVariants",
    R"doc(
    Class representing the ``LC_FUNCTION_VARIANTS`` load command.

    Introduced publicly in ``dyld-1284.13`` (April 2025), this command supports
    **function multiversioning**, the ability to associate multiple implementations
    of the same function, each optimized for a specific platform, architecture,
    or runtime context.

    At runtime, the system dispatches the most appropriate variant based on
    hardware capabilities or execution environment.

    For example:

    .. code-block:: cpp

        FUNCTION_VARIANT_TABLE(my_function,
          { (void*)my_function$Rosetta,  "rosetta" }, // Rosetta translation
          { (void*)my_function$Haswell,  "haswell" }, // Haswell-optimized
          { (void*)my_function$Base,     "default" }  // Default fallback
        );
    )doc"_doc);



  nb::class_<RuntimeTableEntry> runtime_entry(cmd, "RuntimeTableEntry",
    R"doc(
    This class exposes information about a given implementation.
    )doc"_doc
  );

  #define FUNCTION_VARIANT_FLAG(X, _, __) .value(MachO::to_string(FLAGS::X), FLAGS::X)
  nb::enum_<FLAGS>(runtime_entry, "FLAGS")
      #include  "LIEF/MachO/FunctionVariants/Arm64.def"
      #include  "LIEF/MachO/FunctionVariants/PerProcess.def"
      #include  "LIEF/MachO/FunctionVariants/SystemWide.def"
      #include  "LIEF/MachO/FunctionVariants/X86_64.def"
      .value("UNKNOWN", FLAGS::UNKNOWN)
  ;
  #undef FUNCTION_VARIANT_FLAG

  runtime_entry
    .def_prop_ro("impl", &RuntimeTableEntry::impl,
      R"doc(
      The relative address of the implementation or an index if
      :attr:`~.another_table` is set.
      )doc"_doc
    )

    .def_prop_ro("another_table", &RuntimeTableEntry::another_table,
      R"doc(
      Indicates whether :attr:`~.impl` refers to an entry in another runtime table,
      rather than a direct function implementation address.
      )doc"_doc
    )

    .def_prop_ro("flag_bit_nums", &RuntimeTableEntry::flag_bit_nums,
      R"doc(
      The ``flagBitNums`` value as a slice of bytes
      )doc"_doc
    )

    .def_prop_ro("flags", &RuntimeTableEntry::flags,
      R"doc(
      Return the **interpreted** :attr:`~.flag_bit_nums`
      )doc"_doc
    )
    LIEF_DEFAULT_STR(RuntimeTableEntry);

  nb::class_<RuntimeTable> runtime_table(cmd, "RuntimeTable",
    R"doc(
    Represents a runtime table of function variants sharing a common namespace
    (referred to internally as ``FunctionVariantsRuntimeTable`` in ``dyld``).

    Each table holds multiple :class:`~.RuntimeTableEntry` instances that map to
    function implementations optimized for a given :class:`~.RuntimeTable.KIND`.
    )doc"_doc
  );

  nb::enum_<KIND>(runtime_table, "KIND",
    R"doc(
    Enumeration describing the namespace or category of a function variant.

    Each :class:`~.RuntimeTable` is associated with one :class:`~.RuntimeTable.KIND`,
    which indicates the domain or context under which its variant entries
    should be considered valid or applicable.

    These categories map to the runtime dispatch logic used by ``dyld``
    when selecting the optimal function variant.
    )doc"_doc)
    .value("UNKNOWN", KIND::UNKNOWN,
      "Fallback/default kind when the category is not recognized"_doc
    )

    .value("PER_PROCESS", KIND::PER_PROCESS,
      "Variants that apply on a per-process basis"_doc
    )

    .value("SYSTEM_WIDE", KIND::SYSTEM_WIDE,
      "Variants that are selected based on system-wide capabilities or configurations"_doc
    )

    .value("ARM64", KIND::ARM64,
      "Variants optimized for the ARM64 architecture."_doc
    )

    .value("X86_64", KIND::X86_64,
      "Variants optimized for the x86-64 architecture."_doc
    )
  ;

  init_ref_iterator<RuntimeTable::it_entries>(runtime_table, "it_entries");

  runtime_table
    .def_prop_ro("kind", &RuntimeTable::kind,
      "Kind of the runtime table"_doc
    )

    .def_prop_ro("offset", &RuntimeTable::offset,
      "Original offset in the payload"_doc
    )

    .def_prop_ro("entries", nb::overload_cast<>(&RuntimeTable::entries),
      "Iterator over the different :class:`~.RuntimeTableEntry` entries"_doc,
      nb::keep_alive<0, 1>()
    )
    LIEF_DEFAULT_STR(RuntimeTable);
  ;

  init_ref_iterator<FunctionVariants::it_runtime_table>(cmd, "it_runtime_table");

  cmd
    .def_prop_rw("data_offset",
        nb::overload_cast<>(&FunctionVariants::data_offset, nb::const_),
        nb::overload_cast<uint32_t>(&FunctionVariants::data_offset),
        "Offset in the binary where the payload starts"_doc)

    .def_prop_rw("data_size",
        nb::overload_cast<>(&FunctionVariants::data_size, nb::const_),
        nb::overload_cast<uint32_t>(&FunctionVariants::data_size),
        "Size of the payload"_doc)

    .def_prop_ro("content",
        nb::overload_cast<>(&FunctionVariants::content, nb::const_),
        "Payload content"_doc)

    .def_prop_ro("runtime_table", nb::overload_cast<>(&FunctionVariants::runtime_table),
      R"doc(
      Iterator over the different :class:`~.RuntimeTable` entries located in the content
      of this ``__LINKEDIT`` command
      )doc"_doc,
      nb::keep_alive<0, 1>()
    )

  LIEF_DEFAULT_STR(FunctionVariants);

}
}
