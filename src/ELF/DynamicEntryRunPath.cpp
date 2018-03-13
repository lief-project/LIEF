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
#include "LIEF/ELF/DynamicEntryRunPath.hpp"

#include <iomanip>
#include <numeric>
#include <sstream>

namespace LIEF {
namespace ELF {


DynamicEntryRunPath& DynamicEntryRunPath::operator=(const DynamicEntryRunPath&) = default;
DynamicEntryRunPath::DynamicEntryRunPath(const DynamicEntryRunPath&) = default;

DynamicEntryRunPath::DynamicEntryRunPath(void) :
  DynamicEntry::DynamicEntry{DYNAMIC_TAGS::DT_RUNPATH, 0},
  runpath_{}
{}

DynamicEntryRunPath::DynamicEntryRunPath(const std::string& runpath) :
  DynamicEntry::DynamicEntry{DYNAMIC_TAGS::DT_RUNPATH, 0},
  runpath_{runpath}
{}


DynamicEntryRunPath::DynamicEntryRunPath(const std::vector<std::string>& paths) :
  DynamicEntry::DynamicEntry{DYNAMIC_TAGS::DT_RUNPATH, 0},
  runpath_{""}
{
  this->paths(paths);
}



const std::string& DynamicEntryRunPath::name(void) const {
  return this->runpath_;
}


void DynamicEntryRunPath::name(const std::string& name) {
  this->runpath_ = name;
}

const std::string& DynamicEntryRunPath::runpath(void) const {
  return this->name();
}

void DynamicEntryRunPath::runpath(const std::string& runpath) {
  this->name(runpath);
}


std::vector<std::string> DynamicEntryRunPath::paths(void) const {
  std::stringstream ss;
  ss.str(this->runpath());
  std::string path;
  std::vector<std::string> paths;
  while (std::getline(ss, path, DynamicEntryRunPath::delimiter)) {
    paths.push_back(path);
  }
  return paths;
}

void DynamicEntryRunPath::paths(const std::vector<std::string>& paths) {
  this->runpath_ = std::accumulate(
      std::begin(paths),
      std::end(paths),
      std::string(""),
      [] (std::string path, const std::string& new_entry) {
        return path.empty() ? new_entry :  path + DynamicEntryRunPath::delimiter + new_entry;
      });
}

DynamicEntryRunPath& DynamicEntryRunPath::append(const std::string& path) {
  std::vector<std::string> paths = this->paths();
  paths.push_back(path);
  this->paths(paths);
  return *this;
}

DynamicEntryRunPath& DynamicEntryRunPath::remove(const std::string& path) {
  std::vector<std::string> paths = this->paths();
  paths.erase(std::remove_if(
        std::begin(paths),
        std::end(paths),
        [&path] (const std::string& p) {
          return p == path;
        }), std::end(paths));
  this->paths(paths);
  return *this;
}

DynamicEntryRunPath& DynamicEntryRunPath::insert(size_t pos, const std::string path) {
  std::vector<std::string> paths = this->paths();

  if (pos == paths.size()) {
    return this->append(path);
  }

  if (pos > paths.size()) {
    throw corrupted(std::to_string(pos) + " is out of ranges");
  }
  paths.insert(std::begin(paths) + pos, path);
  this->paths(paths);
  return *this;
}

DynamicEntryRunPath& DynamicEntryRunPath::operator+=(const std::string& path) {
  return this->append(path);
}

DynamicEntryRunPath& DynamicEntryRunPath::operator-=(const std::string& path) {
  return this->remove(path);
}

void DynamicEntryRunPath::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& DynamicEntryRunPath::print(std::ostream& os) const {
  DynamicEntry::print(os);
  os << std::hex
     << std::left
     << std::setw(10) << this->name();
  return os;
}
}
}


