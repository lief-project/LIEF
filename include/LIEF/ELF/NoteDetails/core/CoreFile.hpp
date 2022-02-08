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
#ifndef LIEF_ELF_CORE_FILE_H_
#define LIEF_ELF_CORE_FILE_H_

#include <vector>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/ELF/NoteDetails.hpp"

namespace LIEF {
namespace ELF {

class Parser;
class Builder;
class Binary;
class Note;

//! Core file entry
struct CoreFileEntry {
  uint64_t      start;    ///< Start address of mapped file
  uint64_t      end;      ///< End address of mapped file
  uint64_t      file_ofs; ///< Offset (in core) of mapped file
  std::string   path;     ///< Path of mapped file

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const CoreFileEntry& entry);
};

//! Class representing core PrPsInfo object
class LIEF_API CoreFile : public NoteDetails {

  public:
  using NoteDetails::NoteDetails;

  using files_t        = std::vector<CoreFileEntry>;
  using iterator       = files_t::iterator;
  using const_iterator = files_t::const_iterator;

  public:
  static CoreFile make(Note& note);

  CoreFile* clone() const override;

  //! Number of coredump file entries
  uint64_t count() const;

  //! Coredump file entries
  const files_t& files() const;

  iterator begin();
  iterator end();

  const_iterator begin() const;
  const_iterator end() const;

  void files(const files_t&);

  bool operator==(const CoreFile& rhs) const;
  bool operator!=(const CoreFile& rhs) const;

  void dump(std::ostream& os) const override;

  void accept(Visitor& visitor) const override;

  virtual ~CoreFile();

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const CoreFile& note);

  protected:
  template <typename ELF_T>
  LIEF_LOCAL void parse_();

  template <typename ELF_T>
  LIEF_LOCAL void build_();

  void parse() override;
  void build() override;

  private:
  CoreFile(Note& note);

  private:
  files_t  files_;
  uint64_t page_size_;
};

} // namepsace ELF
} // namespace LIEF

#endif
