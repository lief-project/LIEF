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
#include <algorithm>

#include <string>
#include <sstream>

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/DyldInfo.hpp"

#include "pyMachO.hpp"

template<class T>
using getter_t = T (DyldInfo::*)(void) const;

template<class T>
using setter_t = void (DyldInfo::*)(T);

template<class T>
using no_const_getter = T (DyldInfo::*)(void);

void init_MachO_DyldInfo_class(py::module& m) {

  py::class_<DyldInfo, LoadCommand>(m, "DyldInfo")

    .def_property("rebase",
        static_cast<getter_t<const LIEF::MachO::DyldInfo::info_t&>>(&DyldInfo::rebase),
        static_cast<setter_t<const LIEF::MachO::DyldInfo::info_t&>>(&DyldInfo::rebase),
        "*Rebase* information as a tuple ``(offset, size)``\n\n"

        "Dyld rebases an image whenever dyld loads it at an address different \n"
        "from its preferred address. The rebase information is a stream \n"
        "of byte sized opcodes whose symbolic names start with ``REBASE_OPCODE_``. \n"
        "Conceptually the rebase information is a table of tuples: \n"
        "``(seg-index, seg-offset, type)``\n"
        "The opcodes are a compressed way to encode the table by only \n"
        "encoding when a column changes.  In addition simple patterns \n"
        "like \"every n'th offset for m times\" can be encoded in a few \n"
        "bytes.\n\n"

        ".. seealso::\n\n"
        "\t``/usr/include/mach-o/loader.h``\n",
        py::return_value_policy::reference_internal)

    .def_property("rebase_opcodes",
        static_cast<getter_t<const buffer_t&>>(&DyldInfo::rebase_opcodes),
        static_cast<setter_t<const buffer_t&>>(&DyldInfo::rebase_opcodes),
        "Return Rebase's opcodes as ``list`` of bytes")

    .def_property_readonly("show_rebases_opcodes",
        &DyldInfo::show_rebases_opcodes,
        "Return the rebase opcodes in a humman-readable way",
        py::return_value_policy::reference_internal)

    .def_property("bind",
        static_cast<getter_t<const LIEF::MachO::DyldInfo::info_t&>>(&DyldInfo::bind),
        static_cast<setter_t<const LIEF::MachO::DyldInfo::info_t&>>(&DyldInfo::bind),
        "*Bind* information as a tuple ``(offset, size)``\n\n"

        "Dyld binds an image during the loading process, if the image\n"
        "requires any pointers to be initialized to symbols in other images.\n"
        "The rebase information is a stream of byte sized\n"
        "opcodes whose symbolic names start with ``BIND_OPCODE_``.\n"
        "Conceptually the bind information is a table of tuples:\n"
        "``(seg-index, seg-offset, type, symbol-library-ordinal, symbol-name, addend)``\n"
        "The opcodes are a compressed way to encode the table by only\n"
        "encoding when a column changes. In addition simple patterns\n"
        "like for runs of pointers initialzed to the same value can be\n"
        "encoded in a few bytes.\n\n"

        ".. seealso::\n\n"
        "\t``/usr/include/mach-o/loader.h``\n",
        py::return_value_policy::reference_internal)


    .def_property("bind_opcodes",
        static_cast<getter_t<const buffer_t&>>(&DyldInfo::bind_opcodes),
        static_cast<setter_t<const buffer_t&>>(&DyldInfo::bind_opcodes),
        "Return Binding's opcodes as ``list`` of bytes")

    .def_property_readonly("show_bind_opcodes",
        &DyldInfo::show_bind_opcodes,
        "Return the bind opcodes in a humman-readable way",
        py::return_value_policy::reference_internal)


    .def_property("weak_bind",
        static_cast<getter_t<const LIEF::MachO::DyldInfo::info_t&>>(&DyldInfo::weak_bind),
        static_cast<setter_t<const LIEF::MachO::DyldInfo::info_t&>>(&DyldInfo::weak_bind),
        "*Weak Bind* information as a tuple ``(offset, size)``\n\n"

        "Some C++ programs require dyld to unique symbols so that all\n"
        "images in the process use the same copy of some code/data.\n"
        "This step is done after binding. The content of the weak_bind\n"
        "info is an opcode stream like the bind_info.  But it is sorted\n"
        "alphabetically by symbol name. This enable dyld to walk\n"
        "all images with weak binding information in order and look\n"
        "for collisions. If there are no collisions, dyld does\n"
        "no updating. That means that some fixups are also encoded\n"
        "in the bind_info. For instance, all calls to ``operator new`` \n"
        "are first bound to ``libstdc++.dylib`` using the information\n"
        "in bind_info. Then if some image overrides operator new\n"
        "that is detected when the weak_bind information is processed\n"
        "and the call to operator new is then rebound.\n\n"

        ".. seealso::\n\n"
        "\t``/usr/include/mach-o/loader.h``\n",
        py::return_value_policy::reference_internal)


    .def_property("weak_bind_opcodes",
        static_cast<getter_t<const buffer_t&>>(&DyldInfo::weak_bind_opcodes),
        static_cast<setter_t<const buffer_t&>>(&DyldInfo::weak_bind_opcodes),
        "Return **Weak** binding's opcodes as ``list`` of bytes")

    .def_property_readonly("show_weak_bind_opcodes",
        &DyldInfo::show_weak_bind_opcodes,
        "Return the weak bind opcodes in a humman-readable way",
        py::return_value_policy::reference_internal)

    .def_property("lazy_bind",
        static_cast<getter_t<const LIEF::MachO::DyldInfo::info_t&>>(&DyldInfo::lazy_bind),
        static_cast<setter_t<const LIEF::MachO::DyldInfo::info_t&>>(&DyldInfo::lazy_bind),
        "*Lazy Bind* information as a tuple ``(offset, size)``\n\n"

        "Some uses of external symbols do not need to be bound immediately.\n"
        "Instead they can be lazily bound on first use. The lazy_bind\n"
        "are contains a stream of BIND opcodes to bind all lazy symbols.\n"
        "Normal use is that dyld ignores the lazy_bind section when\n"
        "loading an image. Instead the static linker arranged for the\n"
        "lazy pointer to initially point to a helper function which\n"
        "pushes the offset into the lazy_bind area for the symbol\n"
        "needing to be bound, then jumps to dyld which simply adds\n"
        "the offset to lazy_bind_off to get the information on what\n"
        "to bind.\n\n"

        ".. seealso::\n\n"
        "\t``/usr/include/mach-o/loader.h``\n",
        py::return_value_policy::reference_internal)


    .def_property("lazy_bind_opcodes",
        static_cast<getter_t<const buffer_t&>>(&DyldInfo::lazy_bind_opcodes),
        static_cast<setter_t<const buffer_t&>>(&DyldInfo::lazy_bind_opcodes),
        "Return **lazy** binding's opcodes as ``list`` of bytes")

    .def_property_readonly("show_lazy_bind_opcodes",
        &DyldInfo::show_lazy_bind_opcodes,
        "Return the weak bind opcodes in a humman-readable way",
        py::return_value_policy::reference_internal)

    .def_property_readonly("bindings",
        static_cast<no_const_getter<it_binding_info>>(&DyldInfo::bindings),
        "Return an iterator over Dyld's " RST_CLASS_REF(lief.MachO.BindingInfo) "",
        py::return_value_policy::reference_internal)

    .def_property("export_info",
        static_cast<getter_t<const LIEF::MachO::DyldInfo::info_t&>>(&DyldInfo::export_info),
        static_cast<setter_t<const LIEF::MachO::DyldInfo::info_t&>>(&DyldInfo::export_info),
        "*Export* information as a tuple ``(offset, size)``\n\n"

        "The symbols exported by a dylib are encoded in a trie. This\n"
        "is a compact representation that factors out common prefixes.\n"
        "It also reduces ``LINKEDIT`` pages in RAM because it encodes all\n"
        "information (name, address, flags) in one small, contiguous range.\n"
        "The export area is a stream of nodes. The first node sequentially\n"
        "is the start node for the trie.\n\n"

        "Nodes for a symbol start with a byte that is the length of\n"
        "the exported symbol information for the string so far.\n"
        "If there is no exported symbol, the byte is zero. If there\n"
        "is exported info, it follows the length byte. The exported\n"
        "info normally consists of a flags and offset both encoded\n"
        "in `uleb128 <https://en.wikipedia.org/wiki/LEB128>`_. The offset is location of the content named\n"
        "by the symbol. It is the offset from the mach_header for\n"
        "the image.\n\n"

        "After the initial byte and optional exported symbol information\n"
        "is a byte of how many edges (0-255) that this node has leaving\n"
        "it, followed by each edge.\n"
        "Each edge is a zero terminated cstring of the addition chars\n"
        "in the symbol, followed by a uleb128 offset for the node that\n"
        "edge points to.\n\n"

        ".. seealso::\n\n"
        "\t``/usr/include/mach-o/loader.h``\n",
        py::return_value_policy::reference_internal)

    .def_property("export_trie",
        static_cast<getter_t<const buffer_t&>>(&DyldInfo::export_trie),
        static_cast<setter_t<const buffer_t&>>(&DyldInfo::export_trie),
        "Return Export's trie as ``list`` of bytes")

    .def_property_readonly("exports",
        static_cast<no_const_getter<it_export_info>>(&DyldInfo::exports),
        "Return an iterator over Dyld's " RST_CLASS_REF(lief.MachO.ExportInfo) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("show_export_trie",
        &DyldInfo::show_export_trie,
        "Return the export trie in a humman-readable way",
        py::return_value_policy::reference_internal)

    .def("set_rebase_offset",
        &DyldInfo::set_rebase_offset,
        "offset"_a)

    .def("set_rebase_size",
        &DyldInfo::set_rebase_size,
        "size"_a)


    .def("set_bind_offset",
        &DyldInfo::set_bind_offset,
        "offset"_a)

    .def("set_bind_size",
        &DyldInfo::set_bind_size,
        "size"_a)


    .def("set_weak_bind_offset",
        &DyldInfo::set_weak_bind_offset,
        "offset"_a)

    .def("set_weak_bind_size",
        &DyldInfo::set_weak_bind_size,
        "size"_a)


    .def("set_lazy_bind_offset",
        &DyldInfo::set_lazy_bind_offset,
        "offset"_a)

    .def("set_lazy_bind_size",
        &DyldInfo::set_lazy_bind_size,
        "size"_a)


    .def("set_export_offset",
        &DyldInfo::set_export_offset,
        "offset"_a)

    .def("set_export_size",
        &DyldInfo::set_export_size,
        "size"_a)


    .def("__eq__", &DyldInfo::operator==)
    .def("__ne__", &DyldInfo::operator!=)
    .def("__hash__",
        [] (const DyldInfo& info) {
          return Hash::hash(info);
        })


    .def("__str__",
        [] (const DyldInfo& info)
        {
          std::ostringstream stream;
          stream << info;
          std::string str = stream.str();
          return str;
        });

}
