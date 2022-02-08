/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include "LIEF/VDEX/hash.hpp"

#include "pyIterators.hpp"
#include "pyVDEX.hpp"

namespace LIEF {
namespace VDEX {

template<class T>
using no_const_getter = T (File::*)();

template<class T, class P>
using no_const_func = T (File::*)(P);

template<class T>
using getter_t = T (File::*)() const;

template<class T>
using setter_t = void (File::*)(T);

template<>
void create<File>(py::module& m) {

  // File object
  py::class_<File, LIEF::Object> file(m, "File", "VDEX File representation");

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
    .def_property_readonly("header",
        static_cast<no_const_getter<Header&>>(&File::header),
        "Return the VDEX " RST_CLASS_REF(lief.VDEX.Header) "",
        py::return_value_policy::reference)

    .def_property_readonly("dex_files",
        static_cast<no_const_getter<File::it_dex_files>>(&File::dex_files),
        "Return an iterator over " RST_CLASS_REF(lief.DEX.File) "",
        py::return_value_policy::reference)

    .def_property_readonly("dex2dex_json_info",
        &File::dex2dex_json_info)

    .def("__eq__", &File::operator==)
    .def("__ne__", &File::operator!=)
    .def("__hash__",
        [] (const File& file) {
          return Hash::hash(file);
        })


    .def("__str__",
        [] (const File& file)
        {
          std::ostringstream stream;
          stream << file;
          std::string str = stream.str();
          return str;
        });
}

}
}

