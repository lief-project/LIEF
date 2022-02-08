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
#include <string>
#include <sstream>

#include "pyELF.hpp"

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/SysvHash.hpp"

namespace LIEF {
namespace ELF {

template<class T>
using getter_t = T (SysvHash::*)() const;

template<class T>
using setter_t = void (SysvHash::*)(T);

template<>
void create<SysvHash>(py::module& m) {

  py::class_<SysvHash, LIEF::Object>(m, "SysvHash",
    R"delim(
    Class which represents the SYSV hash for the symbols resolution

    References:

      * http://www.linker-aliens.org/blogs/ali/entry/gnu_hash_elf_sections/
      * https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-48031.html
    )delim")
    .def(py::init<>())

    .def_property_readonly("nbucket",
      &SysvHash::nbucket,
      "Return the number of buckets")

    .def_property("nchain",
      static_cast<getter_t<uint32_t>>(&SysvHash::nchain),
      static_cast<setter_t<uint32_t>>(&SysvHash::nchain),
      "Return the number of *chains* (symbol table index)")

    .def_property_readonly("buckets",
      &SysvHash::buckets,
      "Buckets values",
      py::return_value_policy::reference_internal)

    .def_property_readonly("chains",
      &SysvHash::chains,
      "Chains values",
      py::return_value_policy::reference_internal)

    .def("__eq__", &SysvHash::operator==)
    .def("__ne__", &SysvHash::operator!=)
    .def("__hash__",
        [] (const SysvHash& sysvhash) {
          return Hash::hash(sysvhash);
        })


    .def("__str__",
        [] (const SysvHash& sysvhash)
        {
          std::ostringstream stream;
          stream << sysvhash;
          std::string str = stream.str();
          return str;
        });



}

}
}
