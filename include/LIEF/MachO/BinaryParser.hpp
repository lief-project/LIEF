/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#ifndef LIEF_MACHO_BINARY_PARSER_H_
#define LIEF_MACHO_BINARY_PARSER_H_
#include <memory>
#include <string>
#include <vector>

#include "LIEF/types.hpp"
#include "LIEF/visibility.h"
#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/Abstract/Parser.hpp"

#include "LIEF/MachO/Structures.hpp"
#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/LoadCommand.hpp"
#include "LIEF/MachO/EnumToString.hpp"

namespace LIEF {
namespace MachO {

class Parser;

//! @brief Class used to parse **single** binary (i.e. **not** FAT)
//! @see MachO::Parser
class DLL_PUBLIC BinaryParser : public LIEF::Parser {

  friend class MachO::Parser;

  public:
    BinaryParser(const std::string& file);
    BinaryParser(const std::vector<uint8_t>& data, uint64_t fat_offset = 0);
    BinaryParser(void);

    BinaryParser& operator=(const BinaryParser& copy) = delete;
    BinaryParser(const BinaryParser& copy) = delete;

    ~BinaryParser(void);

    Binary* get_binary(void);

  private:
    static std::pair<uint64_t, uint64_t> decode_uleb128(const VectorStream& stream, uint64_t offset);

    BinaryParser(std::unique_ptr<VectorStream>&& stream, uint64_t fat_offset = 0);

    void parse(void);

    template<class MACHO_T>
    void parse_header(void);

    template<class MACHO_T>
    void parse_load_commands(void);

    std::unique_ptr<VectorStream> stream_;
    Binary*                       binary_ ;
    MACHO_TYPES                   type_;
    bool                          is64_;
};


} // namespace MachO
} // namespace LIEF
#endif
