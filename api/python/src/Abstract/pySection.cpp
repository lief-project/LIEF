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
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/ndarray.h>

#include "Abstract/init.hpp"

#include "pyLIEF.hpp"
#include "pySafeString.hpp"
#include "typing.hpp"
#include "nanobind/extra/stl/lief_span.h"
#include "nanobind/utils.hpp"

#include "LIEF/Abstract/Section.hpp"


namespace LIEF::py {

struct search_result : public nanobind::object {
  LIEF_PY_DEFAULT_CTOR(search_result, nanobind::object);

  NB_OBJECT_DEFAULT(search_result, object, "Optional[int]", check)

  static bool check(handle h) {
    return true;
  }
};

template<>
void create<Section>(nb::module_& m) {
  nb::class_<Section, Object>(m, "Section",
      R"delim(
      Class which represents an abstracted section
      )delim"_doc)

    .def_prop_rw("name",
        [] (const Section& obj) {
          return safe_string(obj.name());
        },
        nb::overload_cast<std::string>(&Section::name),
        "Section's name"_doc)

    .def_prop_ro("fullname",
        [] (const Section& obj) {
          return nb::to_bytes(obj.fullname());
        },
        "Return the **fullname** of the section including the trailing bytes"_doc)

    .def_prop_rw("size",
        nb::overload_cast<>(&Section::size, nb::const_),
        nb::overload_cast<uint64_t>(&Section::size),
        "Section's size"_doc)

    .def_prop_rw("offset",
        nb::overload_cast<>(&Section::offset, nb::const_),
        nb::overload_cast<uint64_t>(&Section::offset),
        "Section's file offset"_doc)

    .def_prop_rw("virtual_address",
        nb::overload_cast<>(&Section::virtual_address, nb::const_),
        nb::overload_cast<uint64_t>(&Section::virtual_address),
        "Section's virtual address"_doc)

    .def_prop_rw("content",
        nb::overload_cast<>(&Section::content, nb::const_),
        nb::overload_cast<const std::vector<uint8_t>&>(&Section::content),
        "Section's content"_doc)

    .def_prop_ro("entropy",
        &Section::entropy,
        "Section's entropy"_doc)

    .def("search",
        [] (const Section& self,
            uint64_t number, size_t pos, size_t size) -> search_result
        {
          size_t res = self.search(number, pos, size);
          if (res == Section::npos) {
            return nb::none();
          }
          return nb::cast(res);
        },
        "Look for **integer** within the current section"_doc,
        "number"_a, "pos"_a = 0, "size"_a = 0)

    .def("search",
        [] (const Section& self, nb::bytes bytes, size_t pos) -> search_result
        {
          std::string raw_str(bytes.c_str(), bytes.size());
          const std::vector<uint8_t> raw = {
            std::make_move_iterator(std::begin(raw_str)),
            std::make_move_iterator(std::end(raw_str))
          };
          size_t res = self.search(raw, pos);
          if (res == Section::npos) {
            return nb::none();
          }
          return nb::cast(res);
        },
        "Look for the given bytes within the current section"_doc,
        "bytes"_a, "pos"_a = 0)

    .def("search",
        [](const Section& self, nb::ndarray<const uint8_t, nb::ndim<1>, nb::c_contig> buffer, size_t pos) -> search_result
        {
          LIEF::span<const uint8_t> view{buffer.data(), buffer.size()};
        
          size_t res = self.search(view, pos);
          if (res == Section::npos) {
              return nb::none();
          }
          return nb::cast(res);
        },
        "Look for the given bytes (memoryview/bytes) within the current section"_doc,
        "buffer"_a, "pos"_a = 0)

    .def("search",
        [] (const Section& self,
            const std::string& str, size_t pos) -> search_result
        {
          size_t res = self.search(str, pos);
          if (res == Section::npos) {
            return nb::none();
          }
          return nb::cast(res);
        },
        "Look for the given bytes in string format within the current section"_doc,
        "str"_a, "pos"_a = 0)

    .def("search_string",
        [] (const Section& self,
            const std::string& str, size_t pos) -> search_result
        {
          size_t res = self.search_string(str, pos);
          if (res == Section::npos) {
            return nb::none();
          }
          return nb::cast(res);
        },
        "Look for **string** within the current section"_doc,
        "str"_a, "pos"_a = 0)

    .def("search_all",
        nb::overload_cast<uint64_t, size_t>(&Section::search_all, nb::const_),
        "Look for **all** integers within the current section"_doc,
        "number"_a, "size"_a = 0)

    .def("search_all",
        nb::overload_cast<const std::vector<uint8_t>&>(&Section::search_all, nb::const_),
        "Look for all occurrences of the given bytes in string format within the current section"_doc,
        "number"_a)

    .def("search_all",
        [](const Section& self, nb::ndarray<const uint8_t, nb::ndim<1>, nb::c_contig> buffer) 
        {
          LIEF::span<const uint8_t> view{buffer.data(), buffer.size()};
          return self.search_all(view);
        },
        "Look for all occurrences of the given bytes (memoryview/bytes) within the current section"_doc,
        "buffer"_a)

    .def("search_all",
        nb::overload_cast<const std::string&>(&Section::search_all, nb::const_),
        "Look for all occurrences of the given **list of bytes** within the current section"_doc,
        "number"_a)

    .def("search_string_all",
        nb::overload_cast<const std::string&>(&Section::search_all, nb::const_),
        "Look for all **strings** within the current section"_doc,
        "str"_a)

    LIEF_DEFAULT_STR(Section);

}
}
