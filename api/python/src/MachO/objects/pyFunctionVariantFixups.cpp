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

#include "LIEF/MachO/FunctionVariantFixups.hpp"
#include "LIEF/MachO/SegmentCommand.hpp"

#include "pyIterator.hpp"
#include "MachO/pyMachO.hpp"
#include "nanobind/extra/stl/lief_span.h"

namespace LIEF::MachO::py {

using Fixup = FunctionVariantFixups::Fixup;

template<>
void create<FunctionVariantFixups>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<FunctionVariantFixups, LoadCommand> cmd(m, "FunctionVariantFixups",
    R"doc(
    Class which represents the ``LC_FUNCTION_VARIANT_FIXUPS`` command.

    This command contains the relocations that must be applied to the GOT-like
    slots associated with a :class:`~lief.MachO.FunctionVariants` table. At
    runtime, ``dyld`` resolves each slot to the best implementation and
    (re-)signs it according to the pointer-authentication information.
    )doc"_doc);

  nb::class_<Fixup>(cmd, "Fixup",
    R"doc(
    A single relocation associated with a function-variant. It mirrors the
    ``FunctionVariantFixups::InternalFixup`` structure used by ``dyld`` and
    describes a slot that must be fixed up to point to the variant referenced by
    :attr:`~.variant_index`.
    )doc"_doc)
    .def(nb::init<>())
    .def(nb::init<uint32_t, uint32_t, uint32_t, bool, bool, uint8_t, uint16_t>(),
        "seg_offset"_a, "seg_index"_a, "variant_index"_a, "pac_auth"_a,
        "pac_address"_a, "pac_key"_a, "pac_diversity"_a)

    .def_prop_rw("seg_offset",
        nb::overload_cast<>(&Fixup::seg_offset, nb::const_),
        nb::overload_cast<uint32_t>(&Fixup::seg_offset),
        "Offset of the slot to fix up, relative to :attr:`~.seg_index`"_doc)

    .def_prop_rw("seg_index",
        nb::overload_cast<>(&Fixup::seg_index, nb::const_),
        nb::overload_cast<uint32_t>(&Fixup::seg_index),
        "Index of the segment that owns the slot to fix up"_doc)

    .def_prop_rw("variant_index",
        nb::overload_cast<>(&Fixup::variant_index, nb::const_),
        nb::overload_cast<uint32_t>(&Fixup::variant_index),
        "Index of the FunctionVariants runtime table used to resolve the slot"_doc)

    .def_prop_rw("pac_auth",
        nb::overload_cast<>(&Fixup::pac_auth, nb::const_),
        nb::overload_cast<bool>(&Fixup::pac_auth),
        "Whether the slot is signed with pointer authentication (arm64e)"_doc)

    .def_prop_rw("pac_address",
        nb::overload_cast<>(&Fixup::pac_address, nb::const_),
        nb::overload_cast<bool>(&Fixup::pac_address),
        "Whether the PAC signature mixes the storage address (address diversity)"_doc)

    .def_prop_rw("pac_key",
        nb::overload_cast<>(&Fixup::pac_key, nb::const_),
        nb::overload_cast<uint8_t>(&Fixup::pac_key),
        "PAC key used to sign the slot"_doc)

    .def_prop_rw("pac_diversity",
        nb::overload_cast<>(&Fixup::pac_diversity, nb::const_),
        nb::overload_cast<uint16_t>(&Fixup::pac_diversity),
        "PAC diversity (discriminator) of the slot"_doc)

    .def_prop_ro("segment",
        nb::overload_cast<>(&Fixup::segment),
        "" RST_CLASS_REF(lief.MachO.SegmentCommand) " referenced by "
        ":attr:`~.seg_index` if it could be resolved, or None"_doc,
        nb::rv_policy::reference_internal)
    LIEF_DEFAULT_STR(Fixup);

  init_ref_iterator<FunctionVariantFixups::it_fixups>(cmd, "it_fixups");

  cmd
    .def_prop_rw("data_offset",
        nb::overload_cast<>(&FunctionVariantFixups::data_offset, nb::const_),
        nb::overload_cast<uint32_t>(&FunctionVariantFixups::data_offset),
        "Offset in the binary where the payload starts"_doc)

    .def_prop_rw("data_size",
        nb::overload_cast<>(&FunctionVariantFixups::data_size, nb::const_),
        nb::overload_cast<uint32_t>(&FunctionVariantFixups::data_size),
        "Size of the payload"_doc)

    .def_prop_ro("content",
        nb::overload_cast<>(&FunctionVariantFixups::content, nb::const_),
        "Payload content"_doc)

    .def_prop_ro("fixups", nb::overload_cast<>(&FunctionVariantFixups::fixups),
        "Iterator over the different :class:`~.Fixup` entries"_doc,
        nb::keep_alive<0, 1>())

    .def("add", &FunctionVariantFixups::add,
        "Append a new :class:`~.Fixup`"_doc, "fixup"_a)

  LIEF_DEFAULT_STR(FunctionVariantFixups);

}
}
