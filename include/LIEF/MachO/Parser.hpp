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
#ifndef LIEF_MACHO_PARSER_H_
#define LIEF_MACHO_PARSER_H_
#include <string>
#include <list>

#include "LIEF/types.hpp"
#include "LIEF/visibility.h"
#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/Abstract/Parser.hpp"

#include "LIEF/MachO/ParserConfig.hpp"
#include "LIEF/MachO/Structures.hpp"
#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/FatBinary.hpp"


namespace LIEF {
namespace MachO {
class LIEF_API Parser : public LIEF::Parser {
  public:
    Parser& operator=(const Parser& copy) = delete;
    Parser(const Parser& copy)            = delete;

    ~Parser(void);

    static std::unique_ptr<FatBinary> parse(const std::string& filename, const ParserConfig& conf = ParserConfig::deep());
    static std::unique_ptr<FatBinary> parse(const std::vector<uint8_t>& data, const std::string& name = "", const ParserConfig& conf = ParserConfig::deep());

  private:
    Parser(const std::string& file, const ParserConfig& conf);
    Parser(const std::vector<uint8_t>& data, const std::string& name, const ParserConfig& conf);
    Parser(void);

    void build(void);
    void build_fat(void);

    std::unique_ptr<VectorStream> stream_;
    std::vector<Binary*>          binaries_;
    ParserConfig                  config_;
};
}
}
#endif
