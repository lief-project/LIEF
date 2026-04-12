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
#include "LIEF/rust/Iterator.hpp"
#include "LIEF/ELF/NoteDetails/core/CoreFile.hpp"

class ELF_CoreFile_entry : public Mirror<LIEF::ELF::CoreFile::entry_t> {
  public:
  using lief_t = LIEF::ELF::CoreFile::entry_t;
  using Mirror::Mirror;

  auto start() const {
    return get().start;
  }
  auto end() const {
    return get().end;
  }
  auto file_ofs() const {
    return get().file_ofs;
  }
  std::string path() const {
    return get().path;
  }
};

class ELF_CoreFile : public ELF_Note {
  public:
  using lief_t = LIEF::ELF::CoreFile;
  class it_files : public ContainerIterator<ELF_CoreFile_entry, lief_t::files_t> {
    public:
    it_files(const lief_t& src) :
      ContainerIterator(src.files()) {}

    auto next() {
      return ContainerIterator::next();
    }

    auto size() const {
      return ContainerIterator::size();
    }
  };

  ELF_CoreFile(const lief_t& impl) :
    ELF_Note(static_cast<const LIEF::ELF::Note&>(impl)) {}

  auto count() const {
    return impl().count();
  }

  auto files() const {
    return std::make_unique<it_files>(impl());
  }

  static bool classof(const ELF_Note& note) {
    return lief_t::classof(&note.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
};
