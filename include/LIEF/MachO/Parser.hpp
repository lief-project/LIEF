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
#ifndef LIEF_MACHO_PARSER_H_
#define LIEF_MACHO_PARSER_H_
#include <string>
#include <vector>
#include <memory>

#include "LIEF/types.hpp"
#include "LIEF/errors.hpp"
#include "LIEF/visibility.h"

#include "LIEF/Abstract/Parser.hpp"

#include "LIEF/MachO/ParserConfig.hpp"

struct Profiler;

namespace LIEF {
class BinaryStream;

namespace MachO {
class Binary;
class FatBinary;

//! The main interface to parse a Mach-O binary.
//!
//! This class is used to parse both Fat & non-Fat binary.
//! Non-fat binaries are considerated as a **fat** with
//! only one architecture. This is why MachO::Parser::parse outputs
//! a FatBinary object.
//!
//! @see MachO::Parser
class LIEF_API Parser : public LIEF::Parser {
  public:
  friend struct ::Profiler;
  Parser& operator=(const Parser& copy) = delete;
  Parser(const Parser& copy)            = delete;

  ~Parser();

  //! Parse a Mach-O file from the path provided by the ``filename``
  //! parameter
  //!
  //! The @p conf parameter can be used to tweak the configuration
  //! of the parser
  //!
  //! @param[in] filename   Path to the Mach-O file
  //! @param[in] conf       Parser configuration (Defaut: ParserConfig::deep)
  static std::unique_ptr<FatBinary> parse(const std::string& filename,
                                          const ParserConfig& conf = ParserConfig::deep());

  //! Parse a Mach-O file from the raw content provided by the ``data``
  //! parameter
  //!
  //! The @p conf parameter can be used to tweak the configuration
  //! of the parser
  //!
  //! @param[in] data       Mach-O file as a vector of bytes
  //! @param[in] name       A name for the Mach-O file
  //! @param[in] conf       Parser configuration (Defaut: ParserConfig::deep)
  static std::unique_ptr<FatBinary> parse(const std::vector<uint8_t>& data,
                                          const std::string& name = "",
                                          const ParserConfig& conf = ParserConfig::deep());

  private:
  Parser(const std::string& file, const ParserConfig& conf);
  Parser(std::vector<uint8_t> data, const ParserConfig& conf);
  Parser();

  ok_error_t build();
  ok_error_t build_fat();

  std::unique_ptr<BinaryStream> stream_;
  std::vector<std::unique_ptr<Binary>> binaries_;
  ParserConfig config_;
};
}
}
#endif
