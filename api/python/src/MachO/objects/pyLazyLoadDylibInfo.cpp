/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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

#include "LIEF/MachO/LazyLoadDylibInfo.hpp"

#include "pyIterator.hpp"
#include "MachO/pyMachO.hpp"
#include "nanobind/extra/stl/lief_span.h"

namespace LIEF::MachO::py {

using Fixup = LazyLoadDylibInfo::Fixup;

template<>
void create<LazyLoadDylibInfo>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<LazyLoadDylibInfo, LoadCommand> cmd(m, "LazyLoadDylibInfo",
    R"doc(
    Class representing the ``LC_LAZY_LOAD_DYLIB_INFO`` load command.

    This command describes how to **lazily load a dylib**: instead of binding
    the library and its symbols at launch time, ``dyld`` keeps the information
    required to resolve the dylib on the first use of one of its symbols.
    )doc"_doc);

  nb::class_<Fixup>(cmd, "Fixup",
    R"doc(
    A single lazy-binding fixup decoded from the chain referenced by
    :attr:`~.chain_start_image_offset` and decoded according to :attr:`~.pointer_format`.
    )doc"_doc)
    .def_prop_rw("address",
        nb::overload_cast<>(&Fixup::address, nb::const_),
        nb::overload_cast<uint64_t>(&Fixup::address),
        "Virtual address of the slot bound by this fixup"_doc)

    .def_prop_ro("ordinal", &Fixup::ordinal,
        "Index of the bound symbol in :attr:`~.symbols`"_doc)

    .def_prop_ro("symbol", &Fixup::symbol,
        "Name of the bound symbol (resolved from :attr:`~.ordinal`)"_doc)

    .def_prop_ro("is_auth", &Fixup::is_auth,
        "Whether the bound pointer is authenticated (``arm64e`` PAC)"_doc)

    LIEF_DEFAULT_STR(Fixup);

  init_ref_iterator<LazyLoadDylibInfo::it_fixups>(cmd, "it_fixups");

  cmd
    .def_prop_rw("data_offset",
        nb::overload_cast<>(&LazyLoadDylibInfo::data_offset, nb::const_),
        nb::overload_cast<uint32_t>(&LazyLoadDylibInfo::data_offset),
        "Offset in the ``__LINKEDIT`` segment where the payload starts"_doc)

    .def_prop_rw("data_size",
        nb::overload_cast<>(&LazyLoadDylibInfo::data_size, nb::const_),
        nb::overload_cast<uint32_t>(&LazyLoadDylibInfo::data_size),
        "Size of the payload"_doc)

    .def_prop_ro("content",
        nb::overload_cast<>(&LazyLoadDylibInfo::content, nb::const_),
        "The original content of this payload"_doc)

    .def_prop_rw("load_path",
        nb::overload_cast<>(&LazyLoadDylibInfo::load_path, nb::const_),
        nb::overload_cast<std::string>(&LazyLoadDylibInfo::load_path),
        "Load path of the dylib to bind lazily"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_rw("flag_image_offset",
        nb::overload_cast<>(&LazyLoadDylibInfo::flag_image_offset, nb::const_),
        nb::overload_cast<uint32_t>(&LazyLoadDylibInfo::flag_image_offset),
        "Image offset of the global flag that is set once the dylib has been loaded by dyld"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_rw("flags",
        nb::overload_cast<>(&LazyLoadDylibInfo::flags, nb::const_),
        nb::overload_cast<uint16_t>(&LazyLoadDylibInfo::flags),
        "Raw flags associated with this command (see :attr:`.may_be_missing`)"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_rw("may_be_missing",
        nb::overload_cast<>(&LazyLoadDylibInfo::may_be_missing, nb::const_),
        nb::overload_cast<bool>(&LazyLoadDylibInfo::may_be_missing),
        "Whether the dylib is allowed to be missing at runtime (weak linked)"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_rw("pointer_format",
        nb::overload_cast<>(&LazyLoadDylibInfo::pointer_format, nb::const_),
        nb::overload_cast<uint16_t>(&LazyLoadDylibInfo::pointer_format),
        "Chained-fixups pointer format used by the binding chain"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_rw("chain_start_image_offset",
        nb::overload_cast<>(&LazyLoadDylibInfo::chain_start_image_offset, nb::const_),
        nb::overload_cast<uint32_t>(&LazyLoadDylibInfo::chain_start_image_offset),
        "Image offset of the fixup chain start used to bind the dylib's symbols"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_rw("symbols",
        nb::overload_cast<>(&LazyLoadDylibInfo::symbols, nb::const_),
        nb::overload_cast<std::vector<std::string>>(&LazyLoadDylibInfo::symbols),
        "List of the symbol names to bind lazily for this dylib"_doc,
        nb::rv_policy::reference_internal)

    .def("add_symbol", &LazyLoadDylibInfo::add_symbol,
        "Append a symbol name to the list of symbols to bind lazily"_doc,
        "symbol"_a, nb::rv_policy::reference_internal)

    .def("clear_symbols", &LazyLoadDylibInfo::clear_symbols,
        "Remove all the symbol names to bind lazily"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("fixups", nb::overload_cast<>(&LazyLoadDylibInfo::fixups),
        "Iterator over the lazy-binding :class:`~.Fixup` entries decoded from "
        "the chain"_doc,
        nb::keep_alive<0, 1>())

    LIEF_DEFAULT_STR(LazyLoadDylibInfo);
}

}
