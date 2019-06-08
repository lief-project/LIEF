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
#ifndef LIEF_ELF_NOTE_DETAILS_H_
#define LIEF_ELF_NOTE_DETAILS_H_

#include <vector>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/ELF/Note.hpp"

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
  NoteDetails();

  protected:
  NoteDetails(Note& note);

  public:
  virtual ~NoteDetails(void);

  virtual NoteDetails* clone(void) const;

  const Note::description_t& description(void) const;

  virtual void dump(std::ostream& os) const;

  bool operator==(const NoteDetails& rhs) const;
  bool operator!=(const NoteDetails& rhs) const;

  virtual void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const NoteDetails& note);

  protected:
  virtual void parse(void);
  virtual void build(void);

  Note::description_t& description(void);
  Binary* binary(void);
  const Binary* binary(void) const;

  private:
  Note*                note_;
  Note::description_t  empty_;
};


} // namepsace ELF
} // namespace LIEF

#endif
