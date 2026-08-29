/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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
#ifndef LIEF_VDEX_PARSER_H
#define LIEF_VDEX_PARSER_H

#include <string_view>
#include <memory>
#include <vector>

#include "LIEF/VDEX/type_traits.hpp"
#include "LIEF/path.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
class VectorStream;
namespace VDEX {
class File;

/// Class which parses a VDEX file and transforms it into a VDEX::File object
class LIEF_API Parser {
  public:
  static std::unique_ptr<File> parse(std::string_view file);

  /// Same as parse(std::string_view) but the file is given as a
  /// `std::filesystem::path`
  template<class PathT, enable_if_path_t<PathT> = 0>
  static std::unique_ptr<File> parse(const PathT& file) {
    return parse(file.string());
  }

  static std::unique_ptr<File> parse(const std::vector<uint8_t>& data,
                                     std::string_view name = "");

  Parser& operator=(const Parser& copy) = delete;
  Parser(const Parser& copy) = delete;

  private:
  Parser();
  Parser(std::string_view file);
  Parser(const std::vector<uint8_t>& data, std::string_view name);
  ~Parser();

  void init(std::string_view name, vdex_version_t version);

  template<typename VDEX_T>
  void parse_file();

  template<typename VDEX_T>
  void parse_header();

  template<typename VDEX_T>
  void parse_checksums();

  template<typename VDEX_T>
  void parse_dex_files();

  template<typename VDEX_T>
  void parse_verifier_deps();

  template<typename VDEX_T>
  void parse_quickening_info();

  LIEF::VDEX::File* file_ = nullptr;
  std::unique_ptr<VectorStream> stream_;
};

}
}
#endif
