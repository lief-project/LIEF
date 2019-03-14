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
#ifndef LIEF_ELF_CORE_PSINFO_H_
#define LIEF_ELF_CORE_PSINFO_H_

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

//! Class representing core PrPsInfo object
class LIEF_API CorePrPsInfo : public NoteDetails {

  public:
  using NoteDetails::NoteDetails;

  public:
  static CorePrPsInfo make(Note& note);

  //! Process file name
  std::string file_name(void) const;

  //! Process flag
  uint64_t flags(void) const;

  //! Process user id
  uint32_t uid(void) const;

  //! Process group id
  uint32_t gid(void) const;

  //! Process ID
  int32_t pid(void) const;

  //! Process parent ID
  int32_t ppid(void) const;

  //! Process session group ID
  int32_t pgrp(void) const;

  //! Process session ID
  int32_t sid(void) const;

  void file_name(const std::string& file_name);
  void flags(uint64_t);
  void uid(uint32_t);
  void gid(uint32_t);
  void pid(int32_t);
  void ppid(int32_t);
  void pgrp(int32_t);
  void sid(int32_t);

  bool operator==(const CorePrPsInfo& rhs) const;
  bool operator!=(const CorePrPsInfo& rhs) const;

  virtual void dump(std::ostream& os) const override;

  virtual void accept(Visitor& visitor) const override;

  virtual ~CorePrPsInfo(void);

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const CorePrPsInfo& note);

  protected:
  template <typename ELF_T>
  LIEF_LOCAL void parse_(void);

  template <typename ELF_T>
  LIEF_LOCAL void build_(void);

  virtual void parse(void) override;
  virtual void build(void) override;

  private:
  CorePrPsInfo(Note& note);

  private:
  std::string file_name_;
  uint64_t flags_;
  uint32_t uid_;
  uint32_t gid_;
  int32_t pid_;
  int32_t ppid_;
  int32_t pgrp_;
  int32_t sid_;
};

} // namepsace ELF
} // namespace LIEF

#endif
