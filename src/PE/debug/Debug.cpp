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
#include "LIEF/Visitor.hpp"
#include "LIEF/PE/debug/Debug.hpp"
#include "PE/Structures.hpp"

#include "frozen.hpp"
#include "spdlog/fmt/fmt.h"

namespace LIEF {
namespace PE {

Debug::Debug(const details::pe_debug& debug_s) :
  type_{static_cast<TYPES>(debug_s.Type)},
  characteristics_{debug_s.Characteristics},
  timestamp_{debug_s.TimeDateStamp},
  major_version_{debug_s.MajorVersion},
  minor_version_{debug_s.MinorVersion},
  sizeof_data_{debug_s.SizeOfData},
  addressof_rawdata_{debug_s.AddressOfRawData},
  pointerto_rawdata_{debug_s.PointerToRawData}
{}

void Debug::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const Debug& entry) {
  os << fmt::format("Characteristics:    0x{:x}\n", entry.characteristics())
     << fmt::format("Timestamp:          0x{:x}\n", entry.timestamp())
     << fmt::format("Major/Minor version 0x{:x}/0x{:x}\n", entry.major_version(),
                                                         entry.minor_version())
     << fmt::format("Type:               {}\n", to_string(entry.type()))
     << fmt::format("Size of data:       0x{:x}\n", entry.sizeof_data())
     << fmt::format("Address of rawdata: 0x{:x}\n", entry.addressof_rawdata())
     << fmt::format("Pointer to rawdata: 0x{:x}\n", entry.pointerto_rawdata())
  ;
  return os;
}

const char* to_string(Debug::TYPES e) {
  CONST_MAP(Debug::TYPES, const char*, 18) Enum2Str {
    { Debug::TYPES::UNKNOWN,               "UNKNOWN"               },
    { Debug::TYPES::COFF,                  "COFF"                  },
    { Debug::TYPES::CODEVIEW,              "CODEVIEW"              },
    { Debug::TYPES::FPO,                   "FPO"                   },
    { Debug::TYPES::MISC,                  "MISC"                  },
    { Debug::TYPES::EXCEPTION,             "EXCEPTION"             },
    { Debug::TYPES::FIXUP,                 "FIXUP"                 },
    { Debug::TYPES::OMAP_TO_SRC,           "OMAP_TO_SRC"           },
    { Debug::TYPES::OMAP_FROM_SRC,         "OMAP_FROM_SRC"         },
    { Debug::TYPES::BORLAND,               "BORLAND"               },
    { Debug::TYPES::RESERVED10,            "RESERVED"              },
    { Debug::TYPES::CLSID,                 "CLSID"                 },
    { Debug::TYPES::VC_FEATURE,            "VC_FEATURE"            },
    { Debug::TYPES::POGO,                  "POGO"                  },
    { Debug::TYPES::ILTCG,                 "ILTCG"                 },
    { Debug::TYPES::MPX,                   "MPX"                   },
    { Debug::TYPES::REPRO,                 "REPRO"                 },
    { Debug::TYPES::EX_DLLCHARACTERISTICS, "EX_DLLCHARACTERISTICS" },
  };
  if (const auto it = Enum2Str.find(e); it != Enum2Str.end()) {
    return it->second;
  }
  return "UNKNOWN";
}

}
}

