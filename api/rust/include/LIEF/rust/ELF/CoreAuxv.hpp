/* Copyright 2024 - 2026 R. Thomas
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
#include "LIEF/rust/ELF/Note.hpp"
#include "LIEF/ELF/NoteDetails/core/CoreAuxv.hpp"

class ELF_CoreAuxv : public ELF_Note {
  public:
  using lief_t = LIEF::ELF::CoreAuxv;
  ELF_CoreAuxv(const lief_t& impl) :
    ELF_Note(static_cast<const ELF_Note::lief_t&>(impl)) {}

  auto values() const {
    auto vals = impl().values();
    std::vector<uint64_t> result;
    result.reserve(vals.size() * 2);

    for (const auto& [k, v] : vals) {
      result.push_back((uint64_t)k);
      result.push_back(v);
    }
    return result;
  }

  static bool classof(const ELF_Note& note) {
    return lief_t::classof(&note.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
};
