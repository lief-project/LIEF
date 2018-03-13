/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#include "pyPE.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/resources/LangCodeItem.hpp"

#include <string>
#include <sstream>


template<class T>
using getter_t = T (LangCodeItem::*)(void) const;

template<class T>
using setter_t = void (LangCodeItem::*)(T);

void init_PE_LangCodeItem_class(py::module& m) {
  py::class_<LangCodeItem, LIEF::Object>(m, "LangCodeItem",
      "Class which modelize the childs of the " RST_CLASS_REF(lief.PE.ResourceStringFileInfo) "\n\n"
      "See: https://msdn.microsoft.com/fr-fr/library/windows/desktop/ms646992(v=vs.85).aspx")

    .def_property("type",
        static_cast<getter_t<uint16_t>>(&LangCodeItem::type),
        static_cast<setter_t<uint16_t>>(&LangCodeItem::type),
        "The type of data in the version resource\n\n"
        "\t* ``1`` if it contains text data\n\n"
        "\t* ``0`` if it contains binary data\n\n")

    .def_property("key",
        static_cast<getter_t<const std::u16string&>>(&LangCodeItem::key),
        static_cast<setter_t<const std::string&>>(&LangCodeItem::key),
        "A 8-digit hexadecimal number stored as an Unicode string\n\n"
        "\t* The four most significant digits represent the language identifier.\n\n"
        "\t* The four least significant digits represent the code page for which the data is formatted.\n\n"
        "See:\n"
        "\t* :attr:`~lief.PE.LangCodeItem.code_page`\n\n"
        "\t* :attr:`~lief.PE.LangCodeItem.lang`\n\n"
        "\t* :attr:`~lief.PE.LangCodeItem.sublang`\n\n")

    .def_property("lang",
        static_cast<getter_t<RESOURCE_LANGS>>(&LangCodeItem::lang),
        static_cast<setter_t<RESOURCE_LANGS>>(&LangCodeItem::lang),
        "Lang (" RST_CLASS_REF(lief.PE.RESOURCE_LANGS) ") for which "
        ":attr:`~lief.PE.LangCodeItem.items` are defined")

    .def_property("sublang",
        static_cast<getter_t<RESOURCE_SUBLANGS>>(&LangCodeItem::sublang),
        static_cast<setter_t<RESOURCE_SUBLANGS>>(&LangCodeItem::sublang),
        "Sub-lang (" RST_CLASS_REF(lief.PE.RESOURCE_SUBLANGS) ") for which "
        ":attr:`~lief.PE.LangCodeItem.items` are defined")

    .def_property("code_page",
        static_cast<getter_t<CODE_PAGES>>(&LangCodeItem::code_page),
        static_cast<setter_t<CODE_PAGES>>(&LangCodeItem::code_page),
        "" RST_CLASS_REF(lief.PE.CODE_PAGES) " for which :attr:`~lief.PE.LangCodeItem.items` are defined")

    .def_property("items",
        static_cast<std::map<std::u16string, std::u16string>& (LangCodeItem::*)(void)>(&LangCodeItem::items),
        static_cast<setter_t<const std::map<std::u16string, std::u16string>&>>(&LangCodeItem::items))


    .def("__eq__", &LangCodeItem::operator==)
    .def("__ne__", &LangCodeItem::operator!=)
    .def("__hash__",
        [] (const LangCodeItem& item) {
          return Hash::hash(item);
        })

    .def("__str__",
        [] (const LangCodeItem& item) {
          std::ostringstream stream;
          stream << item;
          std::string str = stream.str();
          return str;
        });
}

