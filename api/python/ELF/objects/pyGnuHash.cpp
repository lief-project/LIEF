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
#include "LIEF/ELF/GnuHash.hpp"

namespace LIEF {
namespace ELF {

template<class T>
using getter_t = T (GnuHash::*)(void) const;

template<class T>
using setter_t = void (GnuHash::*)(T);


template<>
void create<GnuHash>(py::module& m) {
  py::class_<GnuHash, LIEF::Object>(m, "GnuHash",
      R"delim(
      Class which provides a view over the GNU Hash implementation.
      Most of the fields are read-only since the values are re-computed by the :class:`lief.ELF.Builder`.
      )delim")
    .def(py::init<>())

    .def_property_readonly("nb_buckets",
      &GnuHash::nb_buckets,
      "Return the number of buckets")

    .def_property_readonly("symbol_index",
      &GnuHash::symbol_index,
      "Index of the first symbol in the dynamic symbols table which is accessible with the hash table")

    .def_property_readonly("shift2",
      &GnuHash::shift2,
      "Shift count used in the bloom filter")

    .def_property_readonly("bloom_filters",
      &GnuHash::bloom_filters,
      "Bloom filters",
      py::return_value_policy::reference_internal)

    .def_property_readonly("buckets",
      &GnuHash::buckets,
      "hash buckets",
      py::return_value_policy::reference_internal)

    .def_property_readonly("hash_values",
      &GnuHash::hash_values,
      "Hash values",
      py::return_value_policy::reference_internal)

    .def("check_bloom_filter",
        &GnuHash::check_bloom_filter,
        "Check if the given hash pass the bloom filter",
        "hash"_a)

    .def("check_bucket",
        &GnuHash::check_bucket,
        "Check if the given hash pass the bucket filter",
        "hash"_a)

    .def("check",
        static_cast<bool(GnuHash::*)(const std::string&) const>(&GnuHash::check),
        "Check if the symbol *probably* exists. If "
        "the returned value is ``false`` you can assume at ``100%`` that "
        "the symbol with the given name doesn't exists. If ``true`` you can't "
        "do any assumption ",
        "symbol_name"_a)

    .def("check",
        static_cast<bool(GnuHash::*)(uint32_t) const>(&GnuHash::check),
        "Check if the symbol associated with the given *probably* exists. If "
        "the returned value is ``false`` you can assume at ``100%`` that "
        "the symbol doesn't exists. If ``true`` you can't "
        "do any assumption",
        "hash_value"_a)

    .def("__eq__", &GnuHash::operator==)
    .def("__ne__", &GnuHash::operator!=)
    .def("__hash__",
        [] (const GnuHash& gnuhash) {
          return Hash::hash(gnuhash);
        })

    .def("__str__",
        [] (const GnuHash& gnuhash)
        {
          std::ostringstream stream;
          stream << gnuhash;
          std::string str = stream.str();
          return str;
        });
}

}
}

