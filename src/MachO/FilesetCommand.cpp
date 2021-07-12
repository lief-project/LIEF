/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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

#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/Structures.hpp"
#include "LIEF/MachO/FilesetCommand.hpp"

namespace LIEF {
namespace MachO {

FilesetCommand::FilesetCommand(void) = default;

FilesetCommand::FilesetCommand(const fileset_entry_command *filesetCmd) :
  LoadCommand{LOAD_COMMAND_TYPES::LC_FILESET_ENTRY, filesetCmd->cmdsize},
  virtualAddress_{filesetCmd->vmaddr},
  fileOffset_{filesetCmd->fileoff}
{
}

FilesetCommand::FilesetCommand(const std::string& name, const content_t& content) :
  FilesetCommand{}
{
  this->name(name);
  this->content(std::move(content));
}

FilesetCommand::FilesetCommand(const std::string& name) :
  FilesetCommand{}
{
  this->name(name);
}

FilesetCommand& FilesetCommand::operator=(FilesetCommand other) {
  this->swap(other);
  return *this;
}

FilesetCommand::FilesetCommand(const FilesetCommand& other) :
  LoadCommand{other},
  name_{other.name_},
  virtualAddress_{other.virtualAddress_},
  fileOffset_{other.fileOffset_}
{
}

FilesetCommand::~FilesetCommand(void) {
}

void FilesetCommand::swap(FilesetCommand& other) {
  LoadCommand::swap(other);

  std::swap(this->virtualAddress_, other.virtualAddress_);
  std::swap(this->fileOffset_,     other.fileOffset_);
}

FilesetCommand* FilesetCommand::clone(void) const {
  return new FilesetCommand(*this);
}

const std::string& FilesetCommand::name(void) const {
  return this->name_;
}

uint64_t FilesetCommand::virtual_address(void) const {
  return this->virtualAddress_;
}

uint64_t FilesetCommand::file_offset(void) const {
  return this->fileOffset_;
}

const FilesetCommand::content_t& FilesetCommand::content(void) const {
  return this->data_;
}

void FilesetCommand::name(const std::string& name) {
  this->name_ = name;
}

void FilesetCommand::virtual_address(uint64_t virtualAddress) {
  this->virtualAddress_ = virtualAddress;
}

void FilesetCommand::file_offset(uint64_t fileOffset) {
  this->fileOffset_ = fileOffset;
}

void FilesetCommand::content(const FilesetCommand::content_t& data) {
  this->data_ = data;
}

std::ostream& FilesetCommand::print(std::ostream& os) const {

  LoadCommand::print(os);
  os << std::hex;
  os << std::left
     << std::setw(15) << this->name()
     << std::setw(15) << this->virtual_address()
     << std::setw(15) << this->file_offset()
     << std::endl;
  return os;
}

bool FilesetCommand::operator==(const FilesetCommand& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool FilesetCommand::operator!=(const FilesetCommand& rhs) const {
  return not (*this == rhs);
}

}
}
