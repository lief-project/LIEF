/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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
#include "notes_utils.hpp"

namespace LIEF {
namespace ELF {
const note_to_section_map_t& get_note_to_section() {
  static const note_to_section_map_t note_to_section_map = {
    { NOTE_TYPES::NT_GNU_ABI_TAG,              ".note.ABI-tag"          },
    { NOTE_TYPES::NT_GNU_ABI_TAG,              ".note.android.ident"    },

    { NOTE_TYPES::NT_GNU_HWCAP,                ".note.gnu.hwcap"        },
    { NOTE_TYPES::NT_GNU_BUILD_ID,             ".note.gnu.build-id"     },
    { NOTE_TYPES::NT_GNU_BUILD_ID,             ".note.stapsdt"          }, // Alternative name
    { NOTE_TYPES::NT_GNU_GOLD_VERSION,         ".note.gnu.gold-version" },
    { NOTE_TYPES::NT_GNU_GOLD_VERSION,         ".note.go.buildid"       },
    { NOTE_TYPES::NT_GNU_PROPERTY_TYPE_0,      ".note.gnu.property"     },
    { NOTE_TYPES::NT_GNU_BUILD_ATTRIBUTE_OPEN, ".gnu.build.attributes"  },
    { NOTE_TYPES::NT_GNU_BUILD_ATTRIBUTE_FUNC, ".gnu.build.attributes"  },
    { NOTE_TYPES::NT_CRASHPAD,                 ".note.crashpad.info"    },

    { NOTE_TYPES::NT_UNKNOWN,                  ".note"                  },
  };
  return note_to_section_map;
}
}
}
