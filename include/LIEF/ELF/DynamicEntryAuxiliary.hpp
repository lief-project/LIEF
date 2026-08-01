/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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
#ifndef LIEF_ELF_DYNAMIC_ENTRY_AUXILIARY_H
#define LIEF_ELF_DYNAMIC_ENTRY_AUXILIARY_H

#include <string_view>
#include <memory>
#include <string>

#include "LIEF/ELF/DynamicEntry.hpp"
#include "LIEF/compiler_attributes.hpp"
#include "LIEF/visibility.h"


namespace LIEF::ELF {

/// Class which represents a ``DT_AUXILIARY`` entry in the dynamic table
/// This kind of entry is used to specify a shared object that should be
/// loaded before the current one.
class LIEF_API DynamicEntryAuxiliary : public DynamicEntry {

  public:
  using DynamicEntry::DynamicEntry;
  DynamicEntryAuxiliary() :
    DynamicEntry(DynamicEntry::TAG::AUXILIARY, 0) {}

  DynamicEntryAuxiliary(std::string name) :
    DynamicEntry(DynamicEntry::TAG::AUXILIARY, 0),
    name_(std::move(name)) {}

  DynamicEntryAuxiliary& operator=(const DynamicEntryAuxiliary&) = default;
  DynamicEntryAuxiliary(const DynamicEntryAuxiliary&) = default;

  std::unique_ptr<DynamicEntry> clone() const override {
    return std::make_unique<DynamicEntryAuxiliary>(*this);
  }

  /// The actual name (e.g. `libaux.so`)
  std::string_view name() const LIEF_LIFETIMEBOUND {
    return name_;
  }

  void name(std::string name) {
    name_ = std::move(name);
  }

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  static bool classof(const DynamicEntry* entry) {
    return entry->tag() == DynamicEntry::TAG::AUXILIARY;
  }

  ~DynamicEntryAuxiliary() override = default;

  private:
  std::string name_;
};
}

#endif
