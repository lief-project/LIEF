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
#include "DynamicEntry.hpp"

#include "LIEF/ELF/DynamicEntryFlags.hpp"
#include "LIEF/ELF/DynamicSharedObject.hpp"
#include "LIEF/ELF/DynamicEntryLibrary.hpp"
#include "LIEF/ELF/DynamicEntryRpath.hpp"
#include "LIEF/ELF/DynamicEntryRunPath.hpp"
#include "LIEF/ELF/DynamicEntryArray.hpp"

namespace LIEF {
namespace ELF {

void init_c_dynamic_entries(Elf_Binary_t* c_binary, Binary* binary) {

  Binary::it_dynamic_entries dyn_entries = binary->dynamic_entries();
  c_binary->dynamic_entries = static_cast<Elf_DynamicEntry_t**>(
      malloc((dyn_entries.size() + 1) * sizeof(Elf_DynamicEntry_t**)));

  for (size_t i = 0; i < dyn_entries.size(); ++i) {
    DynamicEntry& entry = dyn_entries[i];
    switch(entry.tag()) {
      case DYNAMIC_TAGS::DT_NEEDED:
        {

          auto* e = static_cast<Elf_DynamicEntry_Library_t*>(
              malloc(sizeof(Elf_DynamicEntry_Library_t)));

          e->tag   = static_cast<enum LIEF_ELF_DYNAMIC_TAGS>(entry.tag());
          e->value = entry.value();
          e->name  = reinterpret_cast<DynamicEntryLibrary*>(&entry)->name().c_str();

          c_binary->dynamic_entries[i] = reinterpret_cast<Elf_DynamicEntry_t*>(e);
          break;
        }

      case DYNAMIC_TAGS::DT_SONAME:
        {
          auto* e = static_cast<Elf_DynamicEntry_SharedObject_t*>(
              malloc(sizeof(Elf_DynamicEntry_SharedObject_t)));

          e->tag   = static_cast<enum LIEF_ELF_DYNAMIC_TAGS>(entry.tag());
          e->value = entry.value();
          e->name  = reinterpret_cast<DynamicSharedObject*>(&entry)->name().c_str();

          c_binary->dynamic_entries[i] = reinterpret_cast<Elf_DynamicEntry_t*>(e);
          break;
        }

      case DYNAMIC_TAGS::DT_RPATH:
        {
          auto* e = static_cast<Elf_DynamicEntry_Rpath_t*>(
              malloc(sizeof(Elf_DynamicEntry_Rpath_t)));

          e->tag   = static_cast<enum LIEF_ELF_DYNAMIC_TAGS>(entry.tag());
          e->value = entry.value();
          e->rpath = reinterpret_cast<DynamicEntryRpath*>(&entry)->name().c_str();

          c_binary->dynamic_entries[i] = reinterpret_cast<Elf_DynamicEntry_t*>(e);

          break;
        }

      case DYNAMIC_TAGS::DT_RUNPATH:
        {
          auto* e = static_cast<Elf_DynamicEntry_RunPath_t*>(
              malloc(sizeof(Elf_DynamicEntry_RunPath_t)));

          e->tag   = static_cast<enum LIEF_ELF_DYNAMIC_TAGS>(entry.tag());
          e->value   = entry.value();
          e->runpath = reinterpret_cast<DynamicEntryRunPath*>(&entry)->name().c_str();

          c_binary->dynamic_entries[i] = reinterpret_cast<Elf_DynamicEntry_t*>(e);

          break;
        }

      case DYNAMIC_TAGS::DT_INIT_ARRAY:
      case DYNAMIC_TAGS::DT_FINI_ARRAY:
      case DYNAMIC_TAGS::DT_PREINIT_ARRAY:
        {
          auto* e = static_cast<Elf_DynamicEntry_Array_t*>(
              malloc(sizeof(Elf_DynamicEntry_Array_t)));

          e->tag   = static_cast<enum LIEF_ELF_DYNAMIC_TAGS>(entry.tag());
          e->value = entry.value();
          const std::vector<uint64_t>& array = reinterpret_cast<DynamicEntryArray*>(&entry)->array();
          e->array = static_cast<uint64_t*>(malloc((array.size() + 1) * sizeof(uint64_t)));
          for (size_t i = 0; i < array.size(); ++i) {
            e->array[i] = array[i];
          }
          e->array[array.size()] = 0;
          c_binary->dynamic_entries[i] = reinterpret_cast<Elf_DynamicEntry_t*>(e);

          break;
        }

      case DYNAMIC_TAGS::DT_FLAGS:
        {
          auto* e = static_cast<Elf_DynamicEntry_Flags_t*>(
              malloc(sizeof(Elf_DynamicEntry_Flags_t)));

          e->tag   = static_cast<enum LIEF_ELF_DYNAMIC_TAGS>(entry.tag());
          e->value = entry.value();
          const DynamicEntryFlags::flags_list_t& flags = reinterpret_cast<DynamicEntryFlags*>(&entry)->flags();
          e->flags   = static_cast<enum LIEF_ELF_DYNAMIC_FLAGS*>(malloc((flags.size() + 1) * sizeof(enum LIEF_ELF_DYNAMIC_FLAGS)));
          e->flags_1 = nullptr;

          auto it = std::begin(flags);

          for (size_t i = 0; it != std::end(flags); ++i, ++it) {
            e->flags[i] = static_cast<enum LIEF_ELF_DYNAMIC_FLAGS>(*it);
          }

          e->flags[flags.size()] = static_cast<enum LIEF_ELF_DYNAMIC_FLAGS>(0);
          c_binary->dynamic_entries[i] = reinterpret_cast<Elf_DynamicEntry_t*>(e);

          break;
        }

      case DYNAMIC_TAGS::DT_FLAGS_1:
        {
          auto* e = static_cast<Elf_DynamicEntry_Flags_t*>(
              malloc(sizeof(Elf_DynamicEntry_Flags_t)));

          e->tag   = static_cast<enum LIEF_ELF_DYNAMIC_TAGS>(entry.tag());
          e->value = entry.value();
          const DynamicEntryFlags::flags_list_t& flags = reinterpret_cast<DynamicEntryFlags*>(&entry)->flags();
          e->flags_1 = static_cast<enum LIEF_ELF_DYNAMIC_FLAGS_1*>(malloc((flags.size() + 1) * sizeof(enum LIEF_ELF_DYNAMIC_FLAGS_1)));
          e->flags   = nullptr;

          auto it = std::begin(flags);

          for (size_t i = 0; it != std::end(flags); ++i, ++it) {
            e->flags_1[i] = static_cast<enum LIEF_ELF_DYNAMIC_FLAGS_1>(*it);
          }

          e->flags_1[flags.size()] = static_cast<enum LIEF_ELF_DYNAMIC_FLAGS_1>(0);
          c_binary->dynamic_entries[i] = reinterpret_cast<Elf_DynamicEntry_t*>(e);

          break;
        }




      default:
        {
          c_binary->dynamic_entries[i] =
            static_cast<Elf_DynamicEntry_t*>(malloc(sizeof(Elf_DynamicEntry_t)));
          c_binary->dynamic_entries[i]->tag   = static_cast<enum LIEF_ELF_DYNAMIC_TAGS>(entry.tag());
          c_binary->dynamic_entries[i]->value = entry.value();

        }
    }
  }

  c_binary->dynamic_entries[dyn_entries.size()] = nullptr;

}



void destroy_dynamic_entries(Elf_Binary_t* c_binary) {

  Elf_DynamicEntry_t **dynamic_entries = c_binary->dynamic_entries;
  for (size_t idx = 0; dynamic_entries[idx] != nullptr; ++idx) {
    switch(static_cast<DYNAMIC_TAGS>(dynamic_entries[idx]->tag)) {
      case DYNAMIC_TAGS::DT_NEEDED:
        {
          free(reinterpret_cast<Elf_DynamicEntry_Library_t*>(dynamic_entries[idx]));
          break;
        }

      case DYNAMIC_TAGS::DT_SONAME:
        {
          free(reinterpret_cast<Elf_DynamicEntry_SharedObject_t*>(dynamic_entries[idx]));
          break;
        }

      case DYNAMIC_TAGS::DT_RPATH:
        {
          free(reinterpret_cast<Elf_DynamicEntry_Rpath_t*>(dynamic_entries[idx]));
          break;
        }

      case DYNAMIC_TAGS::DT_RUNPATH:
        {
          free(reinterpret_cast<Elf_DynamicEntry_RunPath_t*>(dynamic_entries[idx]));
          break;
        }

      case DYNAMIC_TAGS::DT_INIT_ARRAY:
      case DYNAMIC_TAGS::DT_FINI_ARRAY:
      case DYNAMIC_TAGS::DT_PREINIT_ARRAY:
        {
          free(reinterpret_cast<Elf_DynamicEntry_Array_t*>(dynamic_entries[idx]));
          break;
        }

      case DYNAMIC_TAGS::DT_FLAGS:
      case DYNAMIC_TAGS::DT_FLAGS_1:
        {
          free(reinterpret_cast<Elf_DynamicEntry_Flags_t*>(dynamic_entries[idx]));
          break;
        }

      default:
        {

          free(dynamic_entries[idx]);
        }


    }
  }
  free(c_binary->dynamic_entries);

}

}
}


