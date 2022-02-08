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
#ifndef LIEF_ELF_NOTE_DETAILS_H_
#define LIEF_ELF_NOTE_DETAILS_H_

#include <vector>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
namespace ELF {

class Parser;
class Builder;
class Binary;
class Note;

class LIEF_API NoteDetails : public Object {

  friend class Parser;
  friend class Builder;
  friend class Binary;

  public:
  using description_t = std::vector<uint8_t>;
  NoteDetails();

  protected:
  NoteDetails(Note& note);

  public:
  virtual ~NoteDetails();

  virtual NoteDetails* clone() const;

  const description_t& description() const;

  virtual void dump(std::ostream& os) const;

  bool operator==(const NoteDetails& rhs) const;
  bool operator!=(const NoteDetails& rhs) const;

  void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const NoteDetails& note);

  protected:
  virtual void parse();
  virtual void build();

  description_t& description();
  Binary* binary();
  const Binary* binary() const;

  private:
  Note* note_{nullptr};
  description_t empty_;
};


} // namepsace ELF
} // namespace LIEF

#endif
