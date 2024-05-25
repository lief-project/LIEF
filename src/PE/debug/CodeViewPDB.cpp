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
#include "LIEF/PE/debug/CodeViewPDB.hpp"
#include "LIEF/Visitor.hpp"
#include "LIEF/BinaryStream/SpanStream.hpp"

#include "spdlog/fmt/fmt.h"
#include "spdlog/fmt/ranges.h"

#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

CodeViewPDB::CodeViewPDB(const details::pe_debug& debug_info,
                         const details::pe_pdb_70& pdb_70) :
  CodeView{debug_info, SIGNATURES::PDB_70},
  age_{pdb_70.age}
{
  std::move(std::begin(pdb_70.signature), std::end(pdb_70.signature),
            std::begin(signature_));
}

void CodeViewPDB::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::string CodeViewPDB::guid() const {
  auto stream = SpanStream::from_array(signature_);
  if (!stream) {
    return "";
  }

  stream->set_endian_swap(true);

  const auto chunk1 = stream->read<uint32_t>().value_or(0);
  const auto chunk2 = stream->read<uint16_t>().value_or(0);
  const auto chunk3 = stream->read<uint16_t>().value_or(0);
  const auto chunk4 = stream->read_conv<uint16_t>().value_or(0);
  const auto chunk5 = stream->read_conv<uint16_t>().value_or(0);
  const auto chunk6 = stream->read_conv<uint32_t>().value_or(0);

  return fmt::format("{:08x}-{:04x}-{:04x}-{:04x}-{:04x}{:08x}",
      chunk1, chunk2, chunk3, chunk4, chunk5, chunk6
  );
}

std::ostream& operator<<(std::ostream& os, const CodeViewPDB& entry) {
  os << static_cast<const CodeView&>(entry) << '\n'
     << fmt::format("[CV][PDB] age:       {}\n", entry.age())
     << fmt::format("[CV][PDB] signature: {}\n", entry.signature())
     << fmt::format("[CV][PDB] GUID:      {}\n", entry.guid())
     << fmt::format("[CV][PDB] filename:  {}\n", entry.filename())
  ;
  return os;
}

}
}
