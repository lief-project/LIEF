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

#include "ELF/pyELF.hpp"
#include "enums_wrapper.hpp"

#include "LIEF/ELF/DynamicEntry.hpp"

namespace LIEF::ELF::py {

template<>
void create<DynamicEntry>(nb::module_& m) {
  nb::class_<DynamicEntry, LIEF::Object> entry(m, "DynamicEntry",
      R"delim(
      Class which represents an entry in the dynamic table
      These entries are located in the ``.dynamic`` section or the ``PT_DYNAMIC`` segment
      )delim"_doc);

  #define ENTRY(X) .value(to_string(DynamicEntry::TAG::X), DynamicEntry::TAG::X)
  enum_<DynamicEntry::TAG>(entry, "TAG")
    ENTRY(UNKNOWN)
    .value("NULL", DynamicEntry::TAG::DT_NULL)
    ENTRY(NEEDED)
    ENTRY(PLTRELSZ)
    ENTRY(PLTGOT)
    ENTRY(HASH)
    ENTRY(STRTAB)
    ENTRY(SYMTAB)
    ENTRY(RELA)
    ENTRY(RELASZ)
    ENTRY(RELAENT)
    ENTRY(STRSZ)
    ENTRY(SYMENT)
    ENTRY(INIT)
    ENTRY(FINI)
    ENTRY(SONAME)
    ENTRY(RPATH)
    ENTRY(SYMBOLIC)
    ENTRY(REL)
    ENTRY(RELSZ)
    ENTRY(RELENT)
    ENTRY(PLTREL)
    ENTRY(DEBUG_TAG)
    ENTRY(TEXTREL)
    ENTRY(JMPREL)
    ENTRY(BIND_NOW)
    ENTRY(INIT_ARRAY)
    ENTRY(FINI_ARRAY)
    ENTRY(INIT_ARRAYSZ)
    ENTRY(FINI_ARRAYSZ)
    ENTRY(RUNPATH)
    ENTRY(FLAGS)
    ENTRY(PREINIT_ARRAY)
    ENTRY(PREINIT_ARRAYSZ)
    ENTRY(SYMTAB_SHNDX)
    ENTRY(RELRSZ)
    ENTRY(RELR)
    ENTRY(RELRENT)
    ENTRY(GNU_HASH)
    ENTRY(RELACOUNT)
    ENTRY(RELCOUNT)
    ENTRY(FLAGS_1)
    ENTRY(VERSYM)
    ENTRY(VERDEF)
    ENTRY(VERDEFNUM)
    ENTRY(VERNEED)
    ENTRY(VERNEEDNUM)
    ENTRY(ANDROID_REL_OFFSET)
    ENTRY(ANDROID_REL_SIZE)
    ENTRY(ANDROID_REL)
    ENTRY(ANDROID_RELSZ)
    ENTRY(ANDROID_RELA)
    ENTRY(ANDROID_RELASZ)
    ENTRY(ANDROID_RELR)
    ENTRY(ANDROID_RELRSZ)
    ENTRY(ANDROID_RELRENT)
    ENTRY(ANDROID_RELRCOUNT)
    ENTRY(MIPS_RLD_VERSION)
    ENTRY(MIPS_TIME_STAMP)
    ENTRY(MIPS_ICHECKSUM)
    ENTRY(MIPS_IVERSION)
    ENTRY(MIPS_FLAGS)
    ENTRY(MIPS_BASE_ADDRESS)
    ENTRY(MIPS_MSYM)
    ENTRY(MIPS_CONFLICT)
    ENTRY(MIPS_LIBLIST)
    ENTRY(MIPS_LOCAL_GOTNO)
    ENTRY(MIPS_CONFLICTNO)
    ENTRY(MIPS_LIBLISTNO)
    ENTRY(MIPS_SYMTABNO)
    ENTRY(MIPS_UNREFEXTNO)
    ENTRY(MIPS_GOTSYM)
    ENTRY(MIPS_HIPAGENO)
    ENTRY(MIPS_RLD_MAP)
    ENTRY(MIPS_DELTA_CLASS)
    ENTRY(MIPS_DELTA_CLASS_NO)
    ENTRY(MIPS_DELTA_INSTANCE)
    ENTRY(MIPS_DELTA_INSTANCE_NO)
    ENTRY(MIPS_DELTA_RELOC)
    ENTRY(MIPS_DELTA_RELOC_NO)
    ENTRY(MIPS_DELTA_SYM)
    ENTRY(MIPS_DELTA_SYM_NO)
    ENTRY(MIPS_DELTA_CLASSSYM)
    ENTRY(MIPS_DELTA_CLASSSYM_NO)
    ENTRY(MIPS_CXX_FLAGS)
    ENTRY(MIPS_PIXIE_INIT)
    ENTRY(MIPS_SYMBOL_LIB)
    ENTRY(MIPS_LOCALPAGE_GOTIDX)
    ENTRY(MIPS_LOCAL_GOTIDX)
    ENTRY(MIPS_HIDDEN_GOTIDX)
    ENTRY(MIPS_PROTECTED_GOTIDX)
    ENTRY(MIPS_OPTIONS)
    ENTRY(MIPS_INTERFACE)
    ENTRY(MIPS_DYNSTR_ALIGN)
    ENTRY(MIPS_INTERFACE_SIZE)
    ENTRY(MIPS_RLD_TEXT_RESOLVE_ADDR)
    ENTRY(MIPS_PERF_SUFFIX)
    ENTRY(MIPS_COMPACT_SIZE)
    ENTRY(MIPS_GP_VALUE)
    ENTRY(MIPS_AUX_DYNAMIC)
    ENTRY(MIPS_PLTGOT)
    ENTRY(MIPS_RWPLT)
    ENTRY(MIPS_RLD_MAP_REL)
    ENTRY(MIPS_XHASH)

    ENTRY(AARCH64_BTI_PLT)
    ENTRY(AARCH64_PAC_PLT)
    ENTRY(AARCH64_VARIANT_PCS)
    ENTRY(AARCH64_MEMTAG_MODE)
    ENTRY(AARCH64_MEMTAG_HEAP)
    ENTRY(AARCH64_MEMTAG_STACK)
    ENTRY(AARCH64_MEMTAG_GLOBALS)
    ENTRY(AARCH64_MEMTAG_GLOBALSSZ)

    ENTRY(HEXAGON_SYMSZ)
    ENTRY(HEXAGON_VER)
    ENTRY(HEXAGON_PLT)

    ENTRY(PPC_GOT)
    ENTRY(PPC_OPT)

    ENTRY(PPC64_GLINK)
    ENTRY(PPC64_OPT)

    ENTRY(RISCV_VARIANT_CC)
  ;
  #undef ENTRY

  entry
    .def(nb::init<>(),
        "Default constructor"_doc)

    .def(nb::init<DynamicEntry::TAG, uint64_t>(),
        "Constructor from a " RST_CLASS_REF(lief.ELF.DynamicEntry.TAG) " and value"_doc,
        "tag"_a, "value"_a)

    .def_prop_rw("tag",
        nb::overload_cast<>(&DynamicEntry::tag, nb::const_),
        nb::overload_cast<DynamicEntry::TAG>(&DynamicEntry::tag),
        "Return the entry's " RST_CLASS_REF(lief.ELF.DynamicEntry.TAG) " which represent the entry type"_doc)

    .def_prop_rw("value",
        nb::overload_cast<>(&DynamicEntry::value, nb::const_),
        nb::overload_cast<uint64_t>(&DynamicEntry::value),
        R"delim(
        Return the entry's value

        The meaning of the value strongly depends on the tag.
        It can be an offset, an index, a flag, ...
        )delim"_doc)

    LIEF_DEFAULT_STR(DynamicEntry);
}

}
