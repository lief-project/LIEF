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
#include "LIEF/ELF/NoteDetails/NoteAbi.hpp"

class ELF_NoteAbi : public ELF_Note {
  public:
  using lief_t = LIEF::ELF::NoteAbi;
  ELF_NoteAbi(const lief_t& impl) :
    ELF_Note(static_cast<const ELF_Note::lief_t&>(impl)) {}

  auto abi() const {
    return to_int(impl().abi().value_or(lief_t::ABI::LINUX));
  }

  std::vector<uint64_t> version() const {
    if (auto res = impl().version()) {
      return to_vector(*res);
    }
    return {};
  }

  static bool classof(const ELF_Note& note) {
    return lief_t::classof(&note.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
};
