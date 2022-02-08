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
#ifndef LIEF_PE_UTILS_LIBRARY_TABLE_H_
#define LIEF_PE_UTILS_LIBRARY_TABLE_H_

#include <unordered_map>

#include "kernel32_dll_lookup.hpp"
#include "ntdll_dll_lookup.hpp"
#include "advapi32_dll_lookup.hpp"
#include "user32_dll_lookup.hpp"
#include "comctl32_dll_lookup.hpp"
#include "ws2_32_dll_lookup.hpp"
#include "shcore_dll_lookup.hpp"
#include "oleaut32_dll_lookup.hpp"
#include "msvcrt_dll_lookup.hpp"
#include "ole32_dll_lookup.hpp"
#include "mfc42u_dll_lookup.hpp"
#include "shlwapi_dll_lookup.hpp"
#include "gdi32_dll_lookup.hpp"
#include "shell32_dll_lookup.hpp"

#include "msvcp110_dll_lookup.hpp"
#include "msvcp120_dll_lookup.hpp"

#include "msvcr100_dll_lookup.hpp"
#include "msvcr110_dll_lookup.hpp"
#include "msvcr120_dll_lookup.hpp"


namespace LIEF {
namespace PE {

static const std::unordered_map<std::string, const char* (*)(uint32_t)>
ordinals_library_tables =
{
  { "kernel32.dll",   &kernel32_dll_lookup },
  { "ntdll.dll",      &ntdll_dll_lookup    },
  { "advapi32.dll",   &advapi32_dll_lookup },
  { "msvcp110.dll",   &msvcp110_dll_lookup },
  { "msvcp120.dll",   &msvcp120_dll_lookup },
  { "msvcr100.dll",   &msvcr100_dll_lookup },
  { "msvcr110.dll",   &msvcr110_dll_lookup },
  { "msvcr120.dll",   &msvcr120_dll_lookup },
  { "user32.dll",     &user32_dll_lookup   },
  { "comctl32.dll",   &comctl32_dll_lookup },
  { "ws2_32.dll",     &ws2_32_dll_lookup   },
  { "shcore.dll",     &shcore_dll_lookup   },
  { "oleaut32.dll",   &oleaut32_dll_lookup },
  { "mfc42u.dll",     &mfc42u_dll_lookup   },
  { "shlwapi.dll",    &shlwapi_dll_lookup  },
  { "gdi32.dll",      &gdi32_dll_lookup    },
  { "shell32.dll",    &shell32_dll_lookup  },
};

}
}

#endif
