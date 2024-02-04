/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include "LIEF/VDEX/File.hpp"
#include "LIEF/DEX/File.hpp"

#include "pyIterator.hpp"

#include "VDEX/pyVDEX.hpp"

#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::VDEX::py {
template<>
void create<File>(nb::module_& m) {
  using namespace LIEF::py;
  nb::class_<File, Object> file(m, "File", "VDEX File representation"_doc);

  /*
   * it_dex_files is also registered by OAT/pyBinary.cpp and pybind11
   * seems not able to see their (limited) scope such as it raises
   *  generic_type: type "it_dex_files" is already registered!
   *
   * NOTE(romain): I tried to add py::local_module in pyIterator.hpp without
   * success
   */
  try {
    init_ref_iterator<File::it_dex_files>(file, "it_dex_files");
  } catch (const std::runtime_error&) {}

  file
    .def_prop_ro("header", nb::overload_cast<>(&File::header),
        "Return the VDEX " RST_CLASS_REF(lief.VDEX.Header) ""_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("dex_files", nb::overload_cast<>(&File::dex_files),
        "Return an iterator over " RST_CLASS_REF(lief.DEX.File) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("dex2dex_json_info", &File::dex2dex_json_info)

    LIEF_DEFAULT_STR(File);
}

}

