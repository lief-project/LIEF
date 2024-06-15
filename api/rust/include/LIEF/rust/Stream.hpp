/* Copyright 2024 R. Thomas
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
#pragma once
#include <memory>

#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/rust/ELF/Binary.hpp"
#include "LIEF/ELF/utils.hpp"
#include "LIEF/ELF/Parser.hpp"

#include "LIEF/rust/PE/Binary.hpp"
#include "LIEF/PE/utils.hpp"
#include "LIEF/PE/Parser.hpp"

#include "LIEF/rust/MachO/FatBinary.hpp"
#include "LIEF/MachO/utils.hpp"
#include "LIEF/MachO/Parser.hpp"

#include "LIEF/visibility.h"

struct IRustStream;

class RustStream {
  public:
  RustStream() = delete;
  RustStream(std::unique_ptr<LIEF::VectorStream> stream) :
    stream_(std::move(stream))
  {}
  LIEF_API
  static std::unique_ptr<RustStream> from_rust(uint8_t* buffer , size_t size);

  bool is_elf() const {
    return LIEF::ELF::is_elf(*stream_);
  }

  bool is_pe() const {
    return LIEF::PE::is_pe(*stream_);
  }

  bool is_macho() const {
    return LIEF::MachO::is_macho(*stream_);
  }

  auto as_elf() {
    return details::try_unique<ELF_Binary>(LIEF::ELF::Parser::parse(std::move(stream_))); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto as_macho() {
    return details::try_unique<MachO_FatBinary>(LIEF::MachO::Parser::parse(std::move(stream_))); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto as_pe() {
    return details::try_unique<PE_Binary>(LIEF::PE::Parser::parse(std::move(stream_))); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  ~RustStream() = default;
  private:
  std::unique_ptr<LIEF::VectorStream> stream_;
};
