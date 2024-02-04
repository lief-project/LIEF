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
#include "PE/pyPE.hpp"

#include "LIEF/PE/resources/LangCodeItem.hpp"
#include "LIEF/utils.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/extra/stl/u16string.h>

namespace LIEF::PE::py {

template<>
void create<LangCodeItem>(nb::module_& m) {
  nb::class_<LangCodeItem, LIEF::Object>(m, "LangCodeItem",
      R"delim(
      Class which represents the childs of the :class:`~lief.PE.ResourceStringFileInfo`

      See: https://docs.microsoft.com/en-us/windows/win32/menurc/stringtable
      )delim"_doc)

    .def_prop_rw("type",
        nb::overload_cast<>(&LangCodeItem::type, nb::const_),
        nb::overload_cast<uint16_t>(&LangCodeItem::type),
        R"delim(
        The type of data in the version resource

          * ``1`` if it contains text data
          * ``0`` if it contains binary data
        )delim"_doc)

    .def_prop_rw("key",
        nb::overload_cast<>(&LangCodeItem::key, nb::const_),
        nb::overload_cast<const std::string&>(&LangCodeItem::key),
        R"delim(
        A 8-digit hexadecimal number stored as an Unicode string

        * The four most significant digits represent the language identifier.
        * The four least significant digits represent the code page for which the data is formatted.

        See:

          * :attr:`~lief.PE.LangCodeItem.code_page`
          * :attr:`~lief.PE.LangCodeItem.lang`
          * :attr:`~lief.PE.LangCodeItem.sublang`

        )delim"_doc)

    .def_prop_rw("lang",
        nb::overload_cast<>(&LangCodeItem::lang, nb::const_),
        nb::overload_cast<uint32_t>(&LangCodeItem::lang),
        "Language for which "
        ":attr:`~lief.PE.LangCodeItem.items` are defined"_doc)

    .def_prop_rw("sublang",
        nb::overload_cast<>(&LangCodeItem::sublang, nb::const_),
        nb::overload_cast<uint32_t>(&LangCodeItem::sublang),
        "Sublanguage for which "
        ":attr:`~lief.PE.LangCodeItem.items` are defined"_doc)

    .def_prop_rw("code_page",
        nb::overload_cast<>(&LangCodeItem::code_page, nb::const_),
        nb::overload_cast<CODE_PAGES>(&LangCodeItem::code_page),
        R"delim(
        :class:`~lief.PE.CODE_PAGES` for which :attr:`~lief.PE.LangCodeItem.items` are defined.

        See: https://docs.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
        )delim"_doc)

    .def_prop_rw("items",
        [] (const LangCodeItem& item) -> nb::dict {
          nb::dict output;
          for (const auto& p : item.items()) {
            const std::string value = u16tou8(p.second);
            output[u16tou8(p.first).c_str()] = nb::bytes(value.c_str(), value.size());
          }
          return output;
        },
        nb::overload_cast<const LangCodeItem::items_t&>(&LangCodeItem::items))

    LIEF_DEFAULT_STR(LangCodeItem);
}

}

