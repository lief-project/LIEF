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
#ifndef LIEF_ELF_CORE_FILE_H_
#define LIEF_ELF_CORE_FILE_H_

#include <vector>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/ELF/Note.hpp"
#include "LIEF/ELF/NoteDetails.hpp"

namespace LIEF {
namespace ELF {

class Parser;
class Builder;
class Binary;

struct CoreFileEntry {
  uint64_t      start;
  uint64_t      end;
  uint64_t      file_ofs;
  std::string   path;
};

//! Class representing core PrPsInfo object
class LIEF_API CoreFile : public NoteDetails {

  public:
  using NoteDetails::NoteDetails;

  public:
  static CoreFile make(Note& note);

  //! Number of coredump file entries
  uint64_t count(void) const;

  //! Coredump file entries
  std::vector<CoreFileEntry> files(void) const;

  void files(const std::vector<CoreFileEntry>&);

  bool operator==(const CoreFile& rhs) const;
  bool operator!=(const CoreFile& rhs) const;

  virtual void dump(std::ostream& os) const override;

  virtual void accept(Visitor& visitor) const override;

  virtual ~CoreFile(void);

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const CoreFile& note);

  protected:
  template <typename ELF_T>
  LIEF_LOCAL void parse_(void);

  template <typename ELF_T>
  LIEF_LOCAL void build_(void);

  virtual void parse(void) override;
  virtual void build(void) override;

  private:
  CoreFile(Note& note);

  private:
  std::vector<CoreFileEntry> files_;
  uint64_t                   page_size_;
};

} // namepsace ELF
} // namespace LIEF

#endif
