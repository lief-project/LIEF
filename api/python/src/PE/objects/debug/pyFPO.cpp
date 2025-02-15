/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
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
#include "PE/pyPE.hpp"
#include "pyIterator.hpp"
#include "LIEF/PE/debug/FPO.hpp"

#include <string>
#include <sstream>
#include "nanobind/utils.hpp"
#include "nanobind/stl/string.h"
#include "enums_wrapper.hpp"

namespace LIEF::PE::py {

template<>
void create<FPO>(nb::module_& m) {
  using namespace LIEF::py;
  nb::class_<FPO, Debug> dbg(m, "FPO",
    R"doc(
    This class represents the ``IMAGE_DEBUG_TYPE_FPO`` debug entry
    )doc"_doc);

  using FRAME_TYPE = FPO::FRAME_TYPE;
  enum_<FRAME_TYPE>(dbg, "FRAME_TYPE")
    .value("FPO", FRAME_TYPE::FPO)
    .value("TRAP", FRAME_TYPE::TRAP)
    .value("TSS", FRAME_TYPE::TSS)
    .value("NON_FPO", FRAME_TYPE::NON_FPO);

  using entry_t = FPO::entry_t;
  nb::class_<entry_t>(dbg, "entry_t",
    R"doc(
    Represents the stack frame layout for a x86 function when frame pointer
    omission (FPO) optimization is used.
    )doc"_doc
  )
    .def_rw("rva", &entry_t::rva,
            "The function RVA"_doc)
    .def_rw("proc_size", &entry_t::proc_size,
            "The number of bytes in the function."_doc)
    .def_rw("nb_locals", &entry_t::nb_locals,
            "The number of local variables."_doc)
    .def_rw("parameters_size", &entry_t::parameters_size,
            "The size of the parameters."_doc)
    .def_rw("prolog_size", &entry_t::prolog_size,
            "The number of bytes in the function prolog code."_doc)
    .def_rw("nb_saved_regs", &entry_t::nb_saved_regs,
            "Number of registers saved."_doc)
    .def_rw("use_seh", &entry_t::use_seh,
            "Whether the function uses structured exception handling."_doc)
    .def_rw("use_bp", &entry_t::use_bp,
            "Whether the EBP register has been allocated."_doc)
    .def_rw("reserved", &entry_t::reserved,
            "reserved for future use"_doc)
    .def_rw("type", &entry_t::type,
            "Variable that indicates the frame type."_doc)
    LIEF_DEFAULT_STR(entry_t);

  init_ref_iterator<FPO::it_entries>(dbg, "it_entries");

  dbg
    .def_prop_ro("entries", nb::overload_cast<>(&FPO::entries),
      "Iterator over the different FPO entries"_doc,
      nb::keep_alive<0, 1>(), nb::rv_policy::reference_internal
    );
}
}
