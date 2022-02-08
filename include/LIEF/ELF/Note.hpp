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
#ifndef LIEF_ELF_NOTE_H_
#define LIEF_ELF_NOTE_H_

#include <vector>
#include <iostream>
#include <memory>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/ELF/enums.hpp"

namespace LIEF {
namespace ELF {

class Parser;
class Builder;
class Binary;
class NoteDetails;

//! Class which represents an ELF note
class LIEF_API Note : public Object {

  friend class Parser;
  friend class Builder;
  friend class Binary;
  friend class NoteDetails;

  public:
  //! Container used to handle the description data
  using description_t = std::vector<uint8_t>;

  public:
  Note();
  Note(std::string  name, uint32_t type, description_t description, Binary* binary=nullptr);
  Note(const std::string& name, NOTE_TYPES type, const description_t& description, Binary* binary=nullptr);
  Note(const std::string& name, NOTE_TYPES_CORE type, const description_t& description, Binary* binary=nullptr);

  Note& operator=(Note copy);
  Note(const Note& copy);

  virtual ~Note();

  //! Return the *name* of the note
  const std::string& name() const;

  //! Return the type of the note. It could be one of the NOTE_TYPES values
  NOTE_TYPES type() const;

  //! Return the type of the note for core ELF (ET_CORE).
  //! It could be one of the NOTE_TYPES_CORE values
  NOTE_TYPES_CORE type_core() const;

  //! Return the description associated with the note
  const description_t& description() const;

  description_t& description();

  //! True if the current note is associated with a core dump
  bool is_core() const;

  //! True if the current note is specific to Android.
  //!
  //! If true, ``details()`` returns a reference to the LIEF::ELF::AndroidNote object
  bool is_android() const;

  const NoteDetails& details() const;
  NoteDetails& details();

  void name(const std::string& name);
  void type(NOTE_TYPES type);
  void type_core(NOTE_TYPES_CORE type);
  void description(const description_t& description);

  //! Size of the **raw** note
  uint64_t size() const;

  virtual void dump(std::ostream& os) const;

  bool operator==(const Note& rhs) const;
  bool operator!=(const Note& rhs) const;

  void swap(Note& other);

  void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Note& note);

  protected:
  Binary*       binary_{nullptr};
  std::string   name_;
  NOTE_TYPES    type_;
  description_t description_;

  private:
  bool is_core_{false};
  std::pair<NOTE_TYPES, std::unique_ptr<NoteDetails>> details_;
};


} // namepsace ELF
} // namespace LIEF

#endif
