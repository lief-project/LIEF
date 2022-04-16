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
#include <algorithm>

#include <string>
#include <sstream>

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/DyldInfo.hpp"

#include "pyIterators.hpp"
#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (DyldInfo::*)(void) const;

template<class T>
using setter_t = void (DyldInfo::*)(T);

template<class T>
using no_const_getter = T (DyldInfo::*)(void);


template<>
void create<DyldInfo>(py::module& m) {

  py::class_<DyldInfo, LoadCommand> dyld(m, "DyldInfo",
      R"delim(
      Class that represents the LC_DYLD_INFO and LC_DYLD_INFO_ONLY commands
      )delim");

  init_ref_iterator<DyldInfo::it_binding_info>(dyld, "it_binding_info");


  try {
    init_ref_iterator<DyldInfo::it_export_info>(dyld, "it_export_info");
  } catch (const std::runtime_error&) { }

  dyld
    .def_property("rebase",
        static_cast<getter_t<const LIEF::MachO::DyldInfo::info_t&>>(&DyldInfo::rebase),
        static_cast<setter_t<const LIEF::MachO::DyldInfo::info_t&>>(&DyldInfo::rebase),
        R"delim(
        *Rebase* information as a tuple ``(offset, size)``

        Dyld rebases an image whenever dyld loads it at an address different
        from its preferred address. The rebase information is a stream
        of byte sized opcodes for which symbolic names start with ``REBASE_OPCODE_``.

        Conceptually the rebase information is a table of tuples: ``(seg-index, seg-offset, type)``

        The opcodes are a compressed way to encode the table by only
        encoding when a column changes.  In addition simple patterns
        like "every n'th offset for m times" can be encoded in a few bytes

        .. seealso::

            ``/usr/include/mach-o/loader.h``
        )delim")

    .def_property("rebase_opcodes",
        [] (const DyldInfo& self) {
          span<const uint8_t> content = self.rebase_opcodes();
          return py::memoryview::from_memory(content.data(), content.size());
        },
        static_cast<setter_t<buffer_t>>(&DyldInfo::rebase_opcodes),
        "Return the rebase's opcodes as ``list`` of bytes")

    .def_property_readonly("show_rebases_opcodes",
        &DyldInfo::show_rebases_opcodes,
        "Return the rebase opcodes in a humman-readable way")

    .def_property("bind",
        static_cast<getter_t<const LIEF::MachO::DyldInfo::info_t&>>(&DyldInfo::bind),
        static_cast<setter_t<const LIEF::MachO::DyldInfo::info_t&>>(&DyldInfo::bind),
        R"delim(
        *Bind* information as a tuple ``(offset, size)``

        Dyld binds an image during the loading process, if the image
        requires any pointers to be initialized to symbols in other images.
        The rebase information is a stream of byte sized opcodes for which symbolic names start with ``BIND_OPCODE_``.

        Conceptually the bind information is a table of tuples:
        ``(seg-index, seg-offset, type, symbol-library-ordinal, symbol-name, addend)``
        The opcodes are a compressed way to encode the table by only encoding when a column changes. In addition simple patterns
        like for runs of pointers initialzed to the same value can be encoded in a few bytes.

        .. seealso::

            ``/usr/include/mach-o/loader.h``
        )delim")


    .def_property("bind_opcodes",
        [] (const DyldInfo& self) {
          span<const uint8_t> content = self.bind_opcodes();
          return py::memoryview::from_memory(content.data(), content.size());
        },
        static_cast<setter_t<buffer_t>>(&DyldInfo::bind_opcodes),
        "Return the binding's opcodes as ``list`` of bytes")

    .def_property_readonly("show_bind_opcodes",
        &DyldInfo::show_bind_opcodes,
        "Return the bind opcodes in a humman-readable way")


    .def_property("weak_bind",
        static_cast<getter_t<const LIEF::MachO::DyldInfo::info_t&>>(&DyldInfo::weak_bind),
        static_cast<setter_t<const LIEF::MachO::DyldInfo::info_t&>>(&DyldInfo::weak_bind),
        R"delim(
        *Weak Bind* information as a tuple ``(offset, size)``

        Some C++ programs require dyld to unique symbols so that all
        images in the process use the same copy of some code/data.

        This step is done after binding.
        The content of the weak_bind info is an opcode stream like the bind_info.
        But it is sorted alphabetically by symbol name. This enables dyld to walk
        all images with weak binding information in order and look for collisions.
        If there are no collisions, dyld does no updating.
        That means that some fixups are also encoded in the bind_info.
        For instance, all calls to ``operator new`` are first bound to ``libstdc++.dylib``
        using the information in bind_info.
        Then if some image overrides operator new that is detected when
        the weak_bind information is processed and the call to operator new is then rebound.

        .. seealso::

            ``/usr/include/mach-o/loader.h``
        )delim")


    .def_property("weak_bind_opcodes",
        [] (const DyldInfo& self) {
          span<const uint8_t> content = self.weak_bind_opcodes();
          return py::memoryview::from_memory(content.data(), content.size());
        },
        static_cast<setter_t<buffer_t>>(&DyldInfo::weak_bind_opcodes),
        "Return **Weak** binding's opcodes as ``list`` of bytes")

    .def_property_readonly("show_weak_bind_opcodes",
        &DyldInfo::show_weak_bind_opcodes,
        "Return the weak bind opcodes in a humman-readable way")

    .def_property("lazy_bind",
        static_cast<getter_t<const LIEF::MachO::DyldInfo::info_t&>>(&DyldInfo::lazy_bind),
        static_cast<setter_t<const LIEF::MachO::DyldInfo::info_t&>>(&DyldInfo::lazy_bind),
        R"delim(
        *Lazy Bind* information as a tuple ``(offset, size)``

        Some uses of external symbols do not need to be bound immediately.
        Instead they can be lazily bound on first use.
        The lazy_bind are contains a stream of BIND opcodes to bind all lazy symbols.
        Normal use is that dyld ignores the lazy_bind section when loading an image.
        Instead the static linker arranged for the lazy pointer to initially point
        to a helper function which pushes the offset into the lazy_bind area for the symbol
        needing to be bound, then jumps to dyld which simply adds the offset to
        lazy_bind_off to get the information on what to bind.

        .. seealso::

            ``/usr/include/mach-o/loader.h``
        )delim")


    .def_property("lazy_bind_opcodes",
        [] (const DyldInfo& self) {
          span<const uint8_t> content = self.lazy_bind_opcodes();
          return py::memoryview::from_memory(content.data(), content.size());
        },
        static_cast<setter_t<buffer_t>>(&DyldInfo::lazy_bind_opcodes),
        "Return **lazy** binding's opcodes as ``list`` of bytes")

    .def_property_readonly("show_lazy_bind_opcodes",
        &DyldInfo::show_lazy_bind_opcodes,
        "Return the weak bind opcodes in a humman-readable way",
        py::return_value_policy::reference_internal)

    .def_property_readonly("bindings",
        static_cast<no_const_getter<DyldInfo::it_binding_info>>(&DyldInfo::bindings),
        "Return an iterator over Dyld's " RST_CLASS_REF(lief.MachO.BindingInfo) "",
        py::return_value_policy::reference_internal)

    .def_property("export_info",
        static_cast<getter_t<const LIEF::MachO::DyldInfo::info_t&>>(&DyldInfo::export_info),
        static_cast<setter_t<const LIEF::MachO::DyldInfo::info_t&>>(&DyldInfo::export_info),
        R"delim(
        *Export* information as a tuple ``(offset, size)``

        The symbols exported by a dylib are encoded in a trie.
        This is a compact representation that factors out common prefixes.

        It also reduces ``LINKEDIT`` pages in RAM because it encodes all
        information (name, address, flags) in one small, contiguous range.
        The export area is a stream of nodes. The first node sequentially
        is the start node for the trie.

        Nodes for a symbol start with a byte that is the length of the exported
        symbol information for the string so far.
        If there is no exported symbol, the byte is zero.
        If there is exported info, it follows the length byte.
        The exported info normally consists of a flags and offset both encoded
        in `uleb128 <https://en.wikipedia.org/wiki/LEB128>`_.
        The offset is location of the content named by the symbol.
        It is the offset from the mach_header for the image.

        After the initial byte and optional exported symbol information
        is a byte of how many edges (0-255) that this node has leaving
        it, followed by each edge.
        Each edge is a zero terminated cstring of the addition chars
        in the symbol, followed by a uleb128 offset for the node that
        edge points to.

        .. seealso::

            ``/usr/include/mach-o/loader.h``
        )delim")


    .def_property("export_trie",
        [] (const DyldInfo& self) {
          span<const uint8_t> content = self.export_trie();
          return py::memoryview::from_memory(content.data(), content.size());
        },
        static_cast<setter_t<buffer_t>>(&DyldInfo::export_trie),
        "Return Export's trie as ``list`` of bytes")

    .def_property_readonly("exports",
        static_cast<no_const_getter<DyldInfo::it_export_info>>(&DyldInfo::exports),
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
        [] (const DyldInfo& info) {
          std::ostringstream stream;
          stream << info;
          std::string str = stream.str();
          return str;
        });

}

}
}
