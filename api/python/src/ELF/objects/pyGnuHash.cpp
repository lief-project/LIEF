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
#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include "ELF/pyELF.hpp"

#include "LIEF/ELF/GnuHash.hpp"

namespace LIEF::ELF::py {

template<>
void create<GnuHash>(nb::module_& m) {
  nb::class_<GnuHash, LIEF::Object>(m, "GnuHash",
      R"delim(
      Class which provides a view over the GNU Hash implementation.
      Most of the fields are read-only since the values are re-computed by the :class:`lief.ELF.Builder`.
      )delim"_doc)
    .def(nb::init<>())

    .def_prop_ro("nb_buckets",
      &GnuHash::nb_buckets,
      "Return the number of buckets"_doc)

    .def_prop_ro("symbol_index",
      &GnuHash::symbol_index,
      "Index of the first symbol in the dynamic symbols table which is accessible with the hash table"_doc)

    .def_prop_ro("shift2",
      &GnuHash::shift2,
      "Shift count used in the bloom filter"_doc)

    .def_prop_ro("bloom_filters",
      &GnuHash::bloom_filters,
      "Bloom filters"_doc,
      nb::rv_policy::reference_internal)

    .def_prop_ro("buckets",
      &GnuHash::buckets,
      "hash buckets"_doc,
      nb::rv_policy::reference_internal)

    .def_prop_ro("hash_values",
      &GnuHash::hash_values,
      "Hash values"_doc,
      nb::rv_policy::reference_internal)

    .def("check_bloom_filter",
        &GnuHash::check_bloom_filter,
        "Check if the given hash pass the bloom filter"_doc,
        "hash"_a)

    .def("check_bucket",
        &GnuHash::check_bucket,
        "Check if the given hash pass the bucket filter"_doc,
        "hash"_a)

    .def("check",
        nb::overload_cast<const std::string&>(&GnuHash::check, nb::const_),
        "Check if the symbol *probably* exists. If "
        "the returned value is ``false`` you can assume at ``100%`` that "
        "the symbol with the given name doesn't exists. If ``true`` you can't "
        "do any assumption "_doc,
        "symbol_name"_a)

    .def("check",
        nb::overload_cast<uint32_t>(&GnuHash::check, nb::const_),
        "Check if the symbol associated with the given *probably* exists. If "
        "the returned value is ``false`` you can assume at ``100%`` that "
        "the symbol doesn't exists. If ``true`` you can't "
        "do any assumption"_doc,
        "hash_value"_a)

    LIEF_DEFAULT_STR(GnuHash);
}

}

