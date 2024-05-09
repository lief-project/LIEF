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

#include "LIEF/MachO/DyldInfo.hpp"
#include "LIEF/MachO/ExportInfo.hpp"
#include "LIEF/MachO/DyldBindingInfo.hpp"

#include "pyIterator.hpp"
#include "nanobind/extra/memoryview.hpp"

#include "MachO/pyMachO.hpp"
#include "enums_wrapper.hpp"

namespace LIEF::MachO::py {

template<>
void create<DyldInfo>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<DyldInfo, LoadCommand> dyld(m, "DyldInfo",
      R"delim(
      Class that represents the LC_DYLD_INFO and LC_DYLD_INFO_ONLY commands
      )delim"_doc);

  enum_<DyldInfo::REBASE_TYPE>(dyld, "REBASE_TYPE")
  #define PY_ENUM(x) to_string(x), x
    .value(PY_ENUM(DyldInfo::REBASE_TYPE::POINTER))
    .value(PY_ENUM(DyldInfo::REBASE_TYPE::TEXT_ABSOLUTE32))
    .value(PY_ENUM(DyldInfo::REBASE_TYPE::TEXT_PCREL32))
    .value(PY_ENUM(DyldInfo::REBASE_TYPE::THREADED))
  #undef PY_ENUM
  ;

  enum_<DyldInfo::REBASE_OPCODES>(dyld, "REBASE_OPCODES")
  #define PY_ENUM(x) to_string(x), x
    .value(PY_ENUM(DyldInfo::REBASE_OPCODES::DONE))
    .value(PY_ENUM(DyldInfo::REBASE_OPCODES::SET_TYPE_IMM))
    .value(PY_ENUM(DyldInfo::REBASE_OPCODES::SET_SEGMENT_AND_OFFSET_ULEB))
    .value(PY_ENUM(DyldInfo::REBASE_OPCODES::ADD_ADDR_ULEB))
    .value(PY_ENUM(DyldInfo::REBASE_OPCODES::ADD_ADDR_IMM_SCALED))
    .value(PY_ENUM(DyldInfo::REBASE_OPCODES::DO_REBASE_IMM_TIMES))
    .value(PY_ENUM(DyldInfo::REBASE_OPCODES::DO_REBASE_ULEB_TIMES))
    .value(PY_ENUM(DyldInfo::REBASE_OPCODES::DO_REBASE_ADD_ADDR_ULEB))
    .value(PY_ENUM(DyldInfo::REBASE_OPCODES::DO_REBASE_ULEB_TIMES_SKIPPING_ULEB))
  #undef PY_ENUM
  ;

  enum_<DyldInfo::BIND_OPCODES>(dyld, "BIND_OPCODES")
  #define PY_ENUM(x) to_string(x), x
    .value(PY_ENUM(DyldInfo::BIND_OPCODES::DONE))
    .value(PY_ENUM(DyldInfo::BIND_OPCODES::SET_DYLIB_ORDINAL_IMM))
    .value(PY_ENUM(DyldInfo::BIND_OPCODES::SET_DYLIB_ORDINAL_ULEB))
    .value(PY_ENUM(DyldInfo::BIND_OPCODES::SET_DYLIB_SPECIAL_IMM))
    .value(PY_ENUM(DyldInfo::BIND_OPCODES::SET_SYMBOL_TRAILING_FLAGS_IMM))
    .value(PY_ENUM(DyldInfo::BIND_OPCODES::SET_TYPE_IMM))
    .value(PY_ENUM(DyldInfo::BIND_OPCODES::SET_ADDEND_SLEB))
    .value(PY_ENUM(DyldInfo::BIND_OPCODES::SET_SEGMENT_AND_OFFSET_ULEB))
    .value(PY_ENUM(DyldInfo::BIND_OPCODES::ADD_ADDR_ULEB))
    .value(PY_ENUM(DyldInfo::BIND_OPCODES::DO_BIND))
    .value(PY_ENUM(DyldInfo::BIND_OPCODES::DO_BIND_ADD_ADDR_ULEB))
    .value(PY_ENUM(DyldInfo::BIND_OPCODES::DO_BIND_ADD_ADDR_IMM_SCALED))
    .value(PY_ENUM(DyldInfo::BIND_OPCODES::DO_BIND_ULEB_TIMES_SKIPPING_ULEB))
    .value(PY_ENUM(DyldInfo::BIND_OPCODES::THREADED))
    .value(PY_ENUM(DyldInfo::BIND_OPCODES::THREADED_APPLY))
    .value(PY_ENUM(DyldInfo::BIND_OPCODES::THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB))
  #undef PY_ENUM
  ;

  init_ref_iterator<DyldInfo::it_binding_info>(dyld, "it_binding_info");

  try {
    init_ref_iterator<DyldInfo::it_export_info>(dyld, "it_export_info");
  } catch (const std::runtime_error&) { }

  dyld
    .def_prop_rw("rebase",
        nb::overload_cast<>(&DyldInfo::rebase, nb::const_),
        nb::overload_cast<const LIEF::MachO::DyldInfo::info_t&>(&DyldInfo::rebase),
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
        )delim"_doc)

    .def_prop_rw("rebase_opcodes",
        [] (const DyldInfo& self) {
          const span<const uint8_t> content = self.rebase_opcodes();
          return nb::memoryview::from_memory(content.data(), content.size());
        },
        nb::overload_cast<buffer_t>(&DyldInfo::rebase_opcodes),
        "Return the rebase's opcodes as ``list`` of bytes"_doc)

    .def_prop_ro("show_rebases_opcodes",
        &DyldInfo::show_rebases_opcodes,
        "Return the rebase opcodes in a humman-readable way"_doc)

    .def_prop_rw("bind",
        nb::overload_cast<>(&DyldInfo::bind, nb::const_),
        nb::overload_cast<const LIEF::MachO::DyldInfo::info_t&>(&DyldInfo::bind),
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
        )delim"_doc)

    .def_prop_rw("bind_opcodes",
        [] (const DyldInfo& self) {
          const span<const uint8_t> content = self.bind_opcodes();
          return nb::memoryview::from_memory(content.data(), content.size());
        },
        nb::overload_cast<buffer_t>(&DyldInfo::bind_opcodes),
        "Return the binding's opcodes as ``list`` of bytes"_doc)

    .def_prop_ro("show_bind_opcodes",
        &DyldInfo::show_bind_opcodes,
        "Return the bind opcodes in a humman-readable way")

    .def_prop_rw("weak_bind",
        nb::overload_cast<>(&DyldInfo::weak_bind, nb::const_),
        nb::overload_cast<const LIEF::MachO::DyldInfo::info_t&>(&DyldInfo::weak_bind),
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
        )delim"_doc)

    .def_prop_rw("weak_bind_opcodes",
        [] (const DyldInfo& self) {
          const span<const uint8_t> content = self.weak_bind_opcodes();
          return nb::memoryview::from_memory(content.data(), content.size());
        },
        nb::overload_cast<buffer_t>(&DyldInfo::weak_bind_opcodes),
        "Return **Weak** binding's opcodes as ``list`` of bytes"_doc)

    .def_prop_ro("show_weak_bind_opcodes",
        &DyldInfo::show_weak_bind_opcodes,
        "Return the weak bind opcodes in a humman-readable way")

    .def_prop_rw("lazy_bind",
        nb::overload_cast<>(&DyldInfo::lazy_bind, nb::const_),
        nb::overload_cast<const LIEF::MachO::DyldInfo::info_t&>(&DyldInfo::lazy_bind),
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
        )delim"_doc)

    .def_prop_rw("lazy_bind_opcodes",
        [] (const DyldInfo& self) {
          const span<const uint8_t> content = self.lazy_bind_opcodes();
          return nb::memoryview::from_memory(content.data(), content.size());
        },
        nb::overload_cast<buffer_t>(&DyldInfo::lazy_bind_opcodes),
        "Return **lazy** binding's opcodes as ``list`` of bytes"_doc)

    .def_prop_ro("show_lazy_bind_opcodes",
        &DyldInfo::show_lazy_bind_opcodes,
        "Return the weak bind opcodes in a humman-readable way"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("bindings",
        nb::overload_cast<>(&DyldInfo::bindings),
        "Return an iterator over Dyld's " RST_CLASS_REF(lief.MachO.BindingInfo) ""_doc,
        nb::rv_policy::reference_internal)

    .def_prop_rw("export_info",
        nb::overload_cast<>(&DyldInfo::export_info, nb::const_),
        nb::overload_cast<const LIEF::MachO::DyldInfo::info_t&>(&DyldInfo::export_info),
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
        )delim"_doc)

    .def_prop_rw("export_trie",
        [] (const DyldInfo& self) {
          const span<const uint8_t> content = self.export_trie();
          return nb::memoryview::from_memory(content.data(), content.size());
        },
        nb::overload_cast<buffer_t>(&DyldInfo::export_trie),
        "Return Export's trie as ``list`` of bytes"_doc)

    .def_prop_ro("exports",
        nb::overload_cast<>(&DyldInfo::exports),
        "Return an iterator over Dyld's " RST_CLASS_REF(lief.MachO.ExportInfo) ""_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("show_export_trie",
        &DyldInfo::show_export_trie,
        "Return the export trie in a humman-readable way"_doc,
        nb::rv_policy::reference_internal)

    .def("set_rebase_offset", &DyldInfo::set_rebase_offset,
         "offset"_a)

    .def("set_rebase_size", &DyldInfo::set_rebase_size,
         "size"_a)

    .def("set_bind_offset", &DyldInfo::set_bind_offset,
         "offset"_a)

    .def("set_bind_size", &DyldInfo::set_bind_size,
         "size"_a)

    .def("set_weak_bind_offset", &DyldInfo::set_weak_bind_offset,
         "offset"_a)

    .def("set_weak_bind_size", &DyldInfo::set_weak_bind_size,
         "size"_a)

    .def("set_lazy_bind_offset", &DyldInfo::set_lazy_bind_offset,
         "offset"_a)

    .def("set_lazy_bind_size", &DyldInfo::set_lazy_bind_size,
         "size"_a)

    .def("set_export_offset", &DyldInfo::set_export_offset,
         "offset"_a)

    .def("set_export_size", &DyldInfo::set_export_size,
         "size"_a)

    LIEF_DEFAULT_STR(DyldInfo);
}
}
