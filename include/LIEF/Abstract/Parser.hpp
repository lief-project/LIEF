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
#ifndef LIEF_ABSTRACT_BUILDER_H_
#define LIEF_ABSTRACT_BUILDER_H_

#include <string>
#include <memory>
#include <vector>

#include "LIEF/visibility.h"

struct Profiler;

namespace LIEF {
class Binary;

//! Main interface to parse an executable regardless of its format
class LIEF_API Parser {
  public:
  friend struct ::Profiler;

  //! Construct an LIEF::Binary from the given filename
  //!
  //! @warning If the target file is a FAT Mach-O, it will return the **last** one
  //! @see LIEF::MachO::Parser::parse
  static std::unique_ptr<Binary> parse(const std::string& filename);


  //! @brief Construct an LIEF::Binary from the given raw data
  //!
  //! @warning If the target file is a FAT Mach-O, it will return the **last** one
  //! @see LIEF::MachO::Parser::parse
  static std::unique_ptr<Binary> parse(const std::vector<uint8_t>& raw, const std::string& name = "");

  protected:
  Parser(const std::string& file);
  uint64_t    binary_size_  = 0;
  std::string binary_name_;

  ~Parser();
  Parser();
};
}

#endif
