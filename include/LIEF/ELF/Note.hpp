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
#ifndef LIEF_ELF_NOTE_H_
#define LIEF_ELF_NOTE_H_

#include <vector>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
namespace ELF {

class Parser;
class Builder;
class Binary;

class LIEF_API Note : public Object {

  friend class Parser;
  friend class Builder;
  friend class Binary;

  public:

  //! Container used to handle the description data
  using description_t = std::vector<uint8_t>;

  //! Type of version
  using version_t = std::array<uint32_t, 3>;

  public:

  //! Default value if the version is unknown
  static constexpr version_t UNKNOWN_VERSION = {{0, 0, 0}};

  public:
  Note(void);
  Note(const std::string& name, uint32_t type, const description_t& description);
  Note(const std::string& name, NOTE_TYPES type, const description_t& description);
  Note& operator=(const Note& copy);
  Note(const Note& copy);
  virtual ~Note(void);

  //! @brief Return the *name* of the note
  const std::string& name(void) const;

  //! @brief Return the type of the note. It could be one of the NOTE_TYPES values
  NOTE_TYPES type(void) const;

  //! @brief Return the description associated with the note
  const description_t& description(void) const;

  description_t& description(void);

  //! @brief Return the target ABI. Require a NT_GNU_ABI_TAG type
  NOTE_ABIS abi(void) const;

  //! @brief Return the target version as ``<Major, Minor, Patch>``.  Require a NT_GNU_ABI_TAG type
  version_t version(void) const;

  void name(const std::string& name);
  void type(NOTE_TYPES type);
  void description(const description_t& description);

  //! @brief Sizeof the **raw** note
  uint64_t size(void) const;

  virtual void dump(std::ostream& os) const;

  bool operator==(const Note& rhs) const;
  bool operator!=(const Note& rhs) const;

  virtual void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Note& note);

  protected:
  std::string   name_;
  NOTE_TYPES    type_;
  description_t description_;
};


} // namepsace ELF
} // namespace LIEF

#endif
