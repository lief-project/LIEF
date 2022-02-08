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
#include "LIEF/OAT/Header.hpp"
#include "LIEF/OAT/hash.hpp"

#include "pyOAT.hpp"

namespace LIEF {
namespace OAT {

template<class T>
using getter_t = T (Header::*)(void) const;

template<class T>
using setter_t = void (Header::*)(T);

template<class T>
using no_const_getter = T (Header::*)(void);

template<>
void create<Header>(py::module& m) {

  py::class_<Header, LIEF::Object> hdr(m, "Header", "OAT Header representation");
  py::class_<Header::it_key_values_t> it_key_values_t(hdr, "it_key_values_t");

  py::class_<Header::it_key_values_t::value_type>(it_key_values_t, "value_type")
    .def_property_readonly("key",
        [] (Header::it_key_values_t::reference p) {
          return p.first;
        }, py::return_value_policy::reference_internal)

    .def_property("value",
        [] (Header::it_key_values_t::reference p) {
         return p.second;
        },
        [] (Header::it_key_values_t::reference p, const std::string& value) {
          std::string& ref_value = p.second;
          ref_value = value;
        },
        py::return_value_policy::reference_internal);

  it_key_values_t
    .def("__getitem__",
        [] (Header::it_key_values_t& v, size_t i) -> Header::it_key_values_t::value_type {
            if (i >= v.size())
                throw py::index_error();
            return v[i];
        },
        py::return_value_policy::reference_internal)

    .def("__len__",
        [](Header::it_key_values_t& v) {
          return  v.size();
        })

    .def("__iter__",
        [](Header::it_key_values_t& v) -> Header::it_key_values_t {
          return std::begin(v);
        }, py::return_value_policy::reference_internal)

    .def("__next__",
        [] (Header::it_key_values_t& v) -> Header::it_key_values_t::value_type {
          if (v == std::end(v)) {
            throw py::stop_iteration();
          }
          return *(v++);

    }, py::return_value_policy::reference_internal);

  hdr
    .def(py::init<>())

    .def_property_readonly("key_values",
        static_cast<no_const_getter<Header::it_key_values_t>>(&Header::key_values),
        "Configuration used for the ``dex2oat`` transformation",
        py::return_value_policy::reference_internal)

    .def_property_readonly("keys",
        &Header::keys,
        "List of " RST_CLASS_REF(lief.OAT.HEADER_KEYS) " present",
        py::return_value_policy::reference_internal)

    .def_property_readonly("values",
        &Header::values,
        "List of values associated with " RST_ATTR_REF(lief.OAT.Header.keys) "",
        py::return_value_policy::move)

    .def_property_readonly("magic",
        static_cast<getter_t<Header::magic_t>>(&Header::magic),
        "Magic number: ``oat\\x0A``")

    .def_property_readonly("version",
        static_cast<getter_t<oat_version_t>>(&Header::version),
        "Underlying version of the OAT file")

    .def_property_readonly("checksum",
        static_cast<getter_t<uint32_t>>(&Header::checksum),
        "Checksum of the OAT file")

    .def_property_readonly("instruction_set",
        static_cast<getter_t<INSTRUCTION_SETS>>(&Header::instruction_set),
        "List of " RST_CLASS_REF(lief.OAT.INSTRUCTION_SETS) "")

    .def_property_readonly("nb_dex_files",
        static_cast<getter_t<uint32_t>>(&Header::nb_dex_files),
        "Number of " RST_CLASS_REF_FULL(lief.DEX.File) " registred in the current OAT")

    .def_property_readonly("oat_dex_files_offset",
        static_cast<getter_t<uint32_t>>(&Header::oat_dex_files_offset),
        "Offset to the raw " RST_CLASS_REF_FULL(lief.OAT.DexFile) "\n\n"
        ".. warning::\n\n"
        "\tThis attribute is only relevant for OAT for which the version is above 131")

    .def_property_readonly("executable_offset",
        static_cast<getter_t<uint32_t>>(&Header::executable_offset))

    .def_property_readonly("i2i_bridge_offset",
        static_cast<getter_t<uint32_t>>(&Header::i2i_bridge_offset))

    .def_property_readonly("i2c_code_bridge_offset",
        static_cast<getter_t<uint32_t>>(&Header::i2c_code_bridge_offset))

    .def_property_readonly("jni_dlsym_lookup_offset",
        static_cast<getter_t<uint32_t>>(&Header::jni_dlsym_lookup_offset))

    .def_property_readonly("quick_generic_jni_trampoline_offset",
        static_cast<getter_t<uint32_t>>(&Header::quick_generic_jni_trampoline_offset))

    .def_property_readonly("quick_imt_conflict_trampoline_offset",
        static_cast<getter_t<uint32_t>>(&Header::quick_imt_conflict_trampoline_offset))

    .def_property_readonly("quick_resolution_trampoline_offset",
        static_cast<getter_t<uint32_t>>(&Header::quick_resolution_trampoline_offset))

    .def_property_readonly("quick_to_interpreter_bridge_offset",
        static_cast<getter_t<uint32_t>>(&Header::quick_to_interpreter_bridge_offset))

    .def_property_readonly("image_patch_delta",
        static_cast<getter_t<int32_t>>(&Header::image_patch_delta))

    .def_property_readonly("image_file_location_oat_checksum",
        static_cast<getter_t<uint32_t>>(&Header::image_file_location_oat_checksum))

    .def_property_readonly("image_file_location_oat_data_begin",
        static_cast<getter_t<uint32_t>>(&Header::image_file_location_oat_data_begin))

    .def_property_readonly("key_value_size",
        static_cast<getter_t<uint32_t>>(&Header::key_value_size))

    .def("get",
        static_cast<const std::string* (Header::*)(HEADER_KEYS) const>(&Header::get),
        "key"_a,
        py::return_value_policy::reference)


    .def("set",
        static_cast<Header& (Header::*)(HEADER_KEYS, const std::string&)>(&Header::set),
        "key"_a, "value"_a,
        py::return_value_policy::reference)

    .def("__getitem__",
        static_cast<const std::string* (Header::*)(HEADER_KEYS) const>(&Header::operator[]),
        "",
        py::return_value_policy::reference)

    .def("__setitem__",
        static_cast<Header& (Header::*)(HEADER_KEYS, const std::string&)>(&Header::set),
        "",
        py::return_value_policy::reference)


    .def("__eq__", &Header::operator==)
    .def("__ne__", &Header::operator!=)
    .def("__hash__",
        [] (const Header& header) {
          return Hash::hash(header);
        })



    .def("__str__",
        [] (const Header& header) {
          std::ostringstream stream;
          stream << header;
          return stream.str();
        });
}

}
}
