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

#include "LIEF/exception.hpp"
#include "LIEF/utils.hpp"
#include "LIEF/BinaryStream/VectorStream.hpp"
#include "LIEF/iostream.hpp"

#include "LIEF/ELF/NoteDetails/core/CoreAuxv.hpp"
#include "LIEF/ELF/Note.hpp"

namespace LIEF {
namespace ELF {

template <typename ELF_T>
void CoreAuxv::parse_() {
  using Elf_Auxv  = typename ELF_T::Elf_Auxv;
  using uint__    = typename ELF_T::uint;

  const Note::description_t& desc = description();
  if (desc.size() < sizeof(Elf_Auxv)) {
    return;
  }

  VectorStream stream(desc);
  while (stream.can_read<Elf_Auxv>()) {
    auto res_auxv = stream.read<Elf_Auxv>();
    if (!res_auxv) {
      break;
    }
    auto auxv = *res_auxv;
    auto type = static_cast<AUX_TYPE>(auxv.a_type);
    if (type == AUX_TYPE::AT_NULL) {
      break;
    }
    ctx_[type] = static_cast<uint__>(auxv.a_un.a_val);
  }

}

template <typename ELF_T>
void CoreAuxv::build_() {
  using Elf_Auxv  = typename ELF_T::Elf_Auxv;
  using uint__    = typename ELF_T::uint;

  Note::description_t& desc = description();

  vector_iostream raw_output;
  raw_output.reserve(ctx_.size() * sizeof(Elf_Auxv));

  for (const auto& val : ctx_) {
    AUX_TYPE type = val.first;
    // skip for now, will be added at the end
    if (type == AUX_TYPE::AT_NULL) {
      continue;
    }
    const Elf_Auxv aux = { static_cast<uint__>(val.first), {static_cast<uint__>(val.second)} };
    raw_output.write_conv(aux);
  }
  // AT_NULL
  const Elf_Auxv terminator = {0, {0}};
  raw_output.write_conv(terminator);

  std::vector<uint8_t> raw = raw_output.raw();
  std::copy(std::begin(raw), std::end(raw),
            std::begin(desc));
}

} // namespace ELF
} // namespace LIEF
