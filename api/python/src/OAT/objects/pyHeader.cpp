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
#include "LIEF/OAT/Header.hpp"

#include "OAT/pyOAT.hpp"

#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/array.h>
#include <nanobind/stl/pair.h>

namespace LIEF::OAT::py {

template<>
void create<Header>(nb::module_& m) {

  nb::class_<Header, Object> hdr(m, "Header", "OAT Header representation"_doc);
  nb::class_<Header::it_key_values_t> it_key_values_t(hdr, "it_key_values_t");

  nb::class_<Header::element_t>(hdr, "element_t")
    .def_rw("key", &Header::element_t::key)
    .def_prop_rw("value",
        [] (const Header::element_t& self) {
          return self.value;
        },
        [] (const Header::element_t& self, const std::string& value) {
          *self.value = value;
        }, nb::rv_policy::reference_internal);


  it_key_values_t
    .def("__getitem__",
        [] (Header::it_key_values_t& v, size_t i) {
            if (i >= v.size()) {
              throw nb::index_error();
            }
            return v[i];
        },
        nb::rv_policy::reference_internal)

    .def("__len__",
        [](Header::it_key_values_t& v) {
          return  v.size();
        })

    .def("__iter__",
        [](Header::it_key_values_t& v) {
          return std::begin(v);
        }, nb::rv_policy::reference_internal)

    .def("__next__",
        [] (Header::it_key_values_t& v) {
          if (v == std::end(v)) {
            throw nb::stop_iteration();
          }
          return *(v++);

    }, nb::rv_policy::reference_internal);

  hdr
    .def(nb::init<>())

    .def_prop_ro("key_values", nb::overload_cast<>(&Header::key_values),
        "Configuration used for the ``dex2oat`` transformation"_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("keys", &Header::keys,
        "List of " RST_CLASS_REF(lief.OAT.HEADER_KEYS) " present"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("values", &Header::values,
        "List of values associated with " RST_ATTR_REF(lief.OAT.Header.keys) ""_doc,
        nb::rv_policy::move)

    .def_prop_ro("magic", nb::overload_cast<>(&Header::magic, nb::const_),
        R"delim(Magic number which shoud be ``oat\x0A``)delim"_doc)

    .def_prop_ro("version", nb::overload_cast<>(&Header::version, nb::const_),
        "Underlying version of the OAT file"_doc)

    .def_prop_ro("checksum", nb::overload_cast<>(&Header::checksum, nb::const_),
        "Checksum of the OAT file"_doc)

    .def_prop_ro("instruction_set",
        nb::overload_cast<>(&Header::instruction_set, nb::const_),
        "List of " RST_CLASS_REF(lief.OAT.INSTRUCTION_SETS) ""_doc)

    .def_prop_ro("nb_dex_files",
        nb::overload_cast<>(&Header::nb_dex_files, nb::const_),
        "Number of " RST_CLASS_REF_FULL(lief.DEX.File) " registred in the current OAT"_doc)

    .def_prop_ro("oat_dex_files_offset",
        nb::overload_cast<>(&Header::oat_dex_files_offset, nb::const_),
        R"delim(
        Offset to the raw  :class:`lief.OAT.Dexfile`

        .. warning::

            This attribute is only relevant for OAT for which the version is above 131
        )delim"_doc)

    .def_prop_ro("executable_offset",
        nb::overload_cast<>(&Header::executable_offset, nb::const_))

    .def_prop_ro("i2i_bridge_offset",
        nb::overload_cast<>(&Header::i2i_bridge_offset, nb::const_))

    .def_prop_ro("i2c_code_bridge_offset",
        nb::overload_cast<>(&Header::i2c_code_bridge_offset, nb::const_))

    .def_prop_ro("jni_dlsym_lookup_offset",
        nb::overload_cast<>(&Header::jni_dlsym_lookup_offset, nb::const_))

    .def_prop_ro("quick_generic_jni_trampoline_offset",
        nb::overload_cast<>(&Header::quick_generic_jni_trampoline_offset, nb::const_))

    .def_prop_ro("quick_imt_conflict_trampoline_offset",
        nb::overload_cast<>(&Header::quick_imt_conflict_trampoline_offset, nb::const_))

    .def_prop_ro("quick_resolution_trampoline_offset",
        nb::overload_cast<>(&Header::quick_resolution_trampoline_offset, nb::const_))

    .def_prop_ro("quick_to_interpreter_bridge_offset",
        nb::overload_cast<>(&Header::quick_to_interpreter_bridge_offset, nb::const_))

    .def_prop_ro("image_patch_delta",
        nb::overload_cast<>(&Header::image_patch_delta, nb::const_))

    .def_prop_ro("image_file_location_oat_checksum",
        nb::overload_cast<>(&Header::image_file_location_oat_checksum, nb::const_))

    .def_prop_ro("image_file_location_oat_data_begin",
        nb::overload_cast<>(&Header::image_file_location_oat_data_begin, nb::const_))

    .def_prop_ro("key_value_size",
        nb::overload_cast<>(&Header::key_value_size, nb::const_))

    .def("get", nb::overload_cast<HEADER_KEYS>(&Header::get),
        "key"_a, nb::rv_policy::reference_internal)

    .def("set",
        nb::overload_cast<HEADER_KEYS, const std::string&>(&Header::set),
        "key"_a, "value"_a, nb::rv_policy::reference_internal)

    .def("__getitem__",
        nb::overload_cast<HEADER_KEYS>(&Header::operator[]),
        nb::rv_policy::reference_internal)

    .def("__setitem__",
        nb::overload_cast<HEADER_KEYS, const std::string&>(&Header::set),
        nb::rv_policy::reference_internal)

    LIEF_DEFAULT_STR(Header);

}

}
