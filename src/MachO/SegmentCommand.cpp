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
#include <iomanip>
#include <memory>

#include "logging.hpp"
#include "LIEF/errors.hpp"
#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/Section.hpp"
#include "LIEF/MachO/Relocation.hpp"
#include "LIEF/MachO/DyldInfo.hpp"
#include "LIEF/MachO/SegmentCommand.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

SegmentCommand::SegmentCommand() = default;
SegmentCommand::~SegmentCommand() = default;

SegmentCommand& SegmentCommand::operator=(SegmentCommand other) {
  swap(other);
  return *this;
}

SegmentCommand::SegmentCommand(const SegmentCommand& other) :
  LoadCommand{other},
  name_{other.name_},
  virtual_address_{other.virtual_address_},
  virtual_size_{other.virtual_size_},
  file_offset_{other.file_offset_},
  file_size_{other.file_size_},
  max_protection_{other.max_protection_},
  init_protection_{other.init_protection_},
  nb_sections_{other.nb_sections_},
  flags_{other.flags_},
  data_{other.data_}
{

  for (const std::unique_ptr<Section>& section : other.sections_) {
    auto new_section = std::make_unique<Section>(*section);
    new_section->segment_ = this;
    new_section->segment_name_ = name();
    sections_.push_back(std::move(new_section));
  }

  // TODO:
  //for (Relocation* relocation : other.relocations_) {
  //  Relocation* new_relocation = relocation->clone();
  //  //relocations_.push_back(new_relocation);
  //}
}



SegmentCommand::SegmentCommand(const details::segment_command_32& seg) :
  LoadCommand{LOAD_COMMAND_TYPES::LC_SEGMENT, seg.cmdsize},
  name_{seg.segname, sizeof(seg.segname)},
  virtual_address_{seg.vmaddr},
  virtual_size_{seg.vmsize},
  file_offset_{seg.fileoff},
  file_size_{seg.filesize},
  max_protection_{seg.maxprot},
  init_protection_{seg.initprot},
  nb_sections_{seg.nsects},
  flags_{seg.flags}
{
  name_ = std::string{name_.c_str()};
}

SegmentCommand::SegmentCommand(const details::segment_command_64& seg) :
  LoadCommand{LOAD_COMMAND_TYPES::LC_SEGMENT_64, seg.cmdsize},
  name_{seg.segname, sizeof(seg.segname)},
  virtual_address_{seg.vmaddr},
  virtual_size_{seg.vmsize},
  file_offset_{seg.fileoff},
  file_size_{seg.filesize},
  max_protection_{seg.maxprot},
  init_protection_{seg.initprot},
  nb_sections_{seg.nsects},
  flags_{seg.flags}
{
  name_ = std::string{name_.c_str()};
}

void SegmentCommand::swap(SegmentCommand& other) {
  LoadCommand::swap(other);

  std::swap(virtual_address_, other.virtual_address_);
  std::swap(virtual_size_,    other.virtual_size_);
  std::swap(file_offset_,     other.file_offset_);
  std::swap(file_size_,       other.file_size_);
  std::swap(max_protection_,  other.max_protection_);
  std::swap(init_protection_, other.init_protection_);
  std::swap(nb_sections_,     other.nb_sections_);
  std::swap(flags_,           other.flags_);
  std::swap(data_,            other.data_);
  std::swap(sections_,        other.sections_);
  std::swap(relocations_,     other.relocations_);
  //std::swap(dyld_,            other.dyld_);
}

SegmentCommand* SegmentCommand::clone() const {
  return new SegmentCommand(*this);
}


SegmentCommand::SegmentCommand(std::string name, content_t content) :
  name_{std::move(name)},
  data_{std::move(content)}
{}


SegmentCommand::SegmentCommand(std::string name) :
  name_{std::move(name)}
{}

const std::string& SegmentCommand::name() const {
  return name_;
}

uint64_t SegmentCommand::virtual_address() const {
  return virtual_address_;
}

uint64_t SegmentCommand::virtual_size() const {
  return virtual_size_;
}

uint64_t SegmentCommand::file_size() const {
  return file_size_;
}

uint64_t SegmentCommand::file_offset() const {
  return file_offset_;
}

uint32_t SegmentCommand::max_protection() const {
  return max_protection_;
}

uint32_t SegmentCommand::init_protection() const {
  return init_protection_;
}

uint32_t SegmentCommand::numberof_sections() const {
  return nb_sections_;
}

uint32_t SegmentCommand::flags() const {
  return flags_;
}

SegmentCommand::it_sections SegmentCommand::sections() {
  return sections_;
}

SegmentCommand::it_const_sections SegmentCommand::sections() const {
  return sections_;
}


SegmentCommand::it_relocations SegmentCommand::relocations() {
  return relocations_;
}

SegmentCommand::it_const_relocations SegmentCommand::relocations() const {
  return relocations_;
}

void SegmentCommand::name(const std::string& name) {
  name_ = name;
}

void SegmentCommand::virtual_address(uint64_t virtual_address) {
  virtual_address_ = virtual_address;
}

void SegmentCommand::virtual_size(uint64_t virtual_size) {
  virtual_size_ = virtual_size;
}

void SegmentCommand::file_size(uint64_t file_size) {
  file_size_ = file_size;
}

void SegmentCommand::file_offset(uint64_t file_offset) {
  file_offset_ = file_offset;
}

void SegmentCommand::max_protection(uint32_t max_protection) {
  max_protection_ = max_protection;
}

void SegmentCommand::init_protection(uint32_t init_protection) {
  init_protection_ = init_protection;
}

void SegmentCommand::numberof_sections(uint32_t nb_sections) {
  nb_sections_ = nb_sections;
}

void SegmentCommand::flags(uint32_t flags) {
  flags_ = flags;
}


void SegmentCommand::content(SegmentCommand::content_t data) {
  update_data([data = std::move(data)] (std::vector<uint8_t>& inner_data) mutable {
                inner_data = std::move(data);
              });
}


void SegmentCommand::remove_all_sections() {
  numberof_sections(0);
  sections_.clear();
}

Section& SegmentCommand::add_section(const Section& section) {
  auto new_section = std::make_unique<Section>(section);

  new_section->segment_ = this;
  new_section->segment_name_ = name();

  new_section->size(section.content().size());

  new_section->offset(file_offset() + file_size());

  if (section.virtual_address() == 0) {
    new_section->virtual_address(virtual_address() + new_section->offset());
  }

  file_size(file_size() + new_section->size());

  const size_t relative_offset = new_section->offset() - file_offset();
  span<const uint8_t> content = section.content();

  update_data([] (std::vector<uint8_t>& inner_data, size_t w, size_t s) {
                inner_data.resize(w + s);
              }, relative_offset, content.size());

  std::copy(std::begin(content), std::end(content),
            std::begin(data_) + relative_offset);

  file_size(data_.size());
  sections_.push_back(std::move(new_section));
  numberof_sections(numberof_sections() + 1);
  return *sections_.back();
}

bool SegmentCommand::has(const Section& section) const {
  auto it = std::find_if(std::begin(sections_), std::end(sections_),
      [&section] (const std::unique_ptr<Section>& sec) {
        return *sec == section;
      });
  return it != std::end(sections_);
}

bool SegmentCommand::has_section(const std::string& section_name) const {
  auto it = std::find_if(std::begin(sections_), std::end(sections_),
      [&section_name] (const std::unique_ptr<Section>& sec) {
        return sec->name() == section_name;
      });
  return it != std::end(sections_);
}



void SegmentCommand::content_resize(size_t size) {
  update_data([size] (std::vector<uint8_t>& inner_data) {
                if (inner_data.size() >= size) {
                  return;
                }
                inner_data.resize(size, 0);
              });
}


void SegmentCommand::content_insert(size_t where, size_t size) {
  update_data([] (std::vector<uint8_t>& inner_data, size_t w, size_t s) {
                if (s == 0) {
                  return;
                }
                if (w < inner_data.size()) {
                  inner_data.insert(std::begin(inner_data) + w, s, 0);
                } else {
                  inner_data.resize(inner_data.size() + w + s, 0);
                }
              }, where, size);
}

const Section* SegmentCommand::get_section(const std::string& name) const {
  const auto it = std::find_if(std::begin(sections_), std::end(sections_),
      [&name] (const std::unique_ptr<Section>& sec) {
        return sec->name() == name;
      });

  if (it == std::end(sections_)) {
    return nullptr;
  }

  return it->get();
}

Section* SegmentCommand::get_section(const std::string& name) {
  return const_cast<Section*>(static_cast<const SegmentCommand*>(this)->get_section(name));
}


void SegmentCommand::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool SegmentCommand::operator==(const SegmentCommand& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool SegmentCommand::operator!=(const SegmentCommand& rhs) const {
  return !(*this == rhs);
}

bool SegmentCommand::classof(const LoadCommand* cmd) {
  // This must be sync with BinaryParser.tcc
  const LOAD_COMMAND_TYPES type = cmd->command();
  return type == LOAD_COMMAND_TYPES::LC_SEGMENT_64 ||
         type == LOAD_COMMAND_TYPES::LC_SEGMENT;
}

std::ostream& SegmentCommand::print(std::ostream& os) const {

  LoadCommand::print(os);
  os << std::hex;
  os << std::left
     << std::setw(15) << name()
     << std::setw(15) << virtual_address()
     << std::setw(15) << virtual_size()
     << std::setw(15) << file_offset()
     << std::setw(15) << file_size()
     << std::setw(15) << max_protection()
     << std::setw(15) << init_protection()
     << std::setw(15) << numberof_sections()
     << std::setw(15) << flags()
     << std::endl;

  os << "Sections in this segment :" << std::endl;
  for (const Section& section : sections()) {
    os << "\t" << section << std::endl;
  }

  return os;
}

void SegmentCommand::update_data(SegmentCommand::update_fnc_t f) {
  f(data_);
}

void SegmentCommand::update_data(SegmentCommand::update_fnc_ws_t f, size_t where, size_t size) {
  f(data_, where, size);
}

}
}
