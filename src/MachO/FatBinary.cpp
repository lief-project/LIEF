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
#include <utility>

#include "LIEF/MachO/FatBinary.hpp"
#include "LIEF/MachO/Builder.hpp"
#include "LIEF/MachO/Binary.hpp"

namespace LIEF {
namespace MachO {

FatBinary::~FatBinary() = default;
FatBinary::FatBinary() = default;

FatBinary::FatBinary(binaries_t binaries) :
  binaries_{std::move(binaries)}
{}

std::unique_ptr<Binary> FatBinary::pop_back() {
  if (binaries_.empty()) {
    return nullptr;
  }
  std::unique_ptr<Binary> last = std::move(binaries_.back());
  binaries_.pop_back();
  return last;
}

std::unique_ptr<Binary> FatBinary::take(Header::CPU_TYPE cpu) {
  auto it = std::find_if(std::begin(binaries_), std::end(binaries_),
      [cpu] (const std::unique_ptr<Binary>& bin) {
        return bin->header().cpu_type() == cpu;
      });

  if (it == std::end(binaries_)) {
    return nullptr;
  }

  std::unique_ptr<Binary> ret = std::move(*it);
  binaries_.erase(it);
  return ret;
}


const Binary* FatBinary::get(Header::CPU_TYPE cpu) const {
  auto it = std::find_if(binaries_.begin(), binaries_.end(),
    [cpu] (const std::unique_ptr<Binary>& bin) {
      return bin->header().cpu_type() == cpu;
    }
  );
  if (it == binaries_.end()) {
    return nullptr;
  }
  return it->get();
}

std::unique_ptr<Binary> FatBinary::take(size_t index) {
  if (index >= binaries_.size()) {
    return nullptr;
  }
  auto it = binaries_.begin();
  std::advance(it, index);
  std::unique_ptr<Binary> ret = std::move(*it);
  binaries_.erase(it);
  return ret;
}

void FatBinary::write(const std::string& filename) {
  Builder::write(*this, filename);
}

std::vector<uint8_t> FatBinary::raw() {
  std::vector<uint8_t> buffer;
  Builder::write(*this, buffer);
  return buffer;
}

std::ostream& operator<<(std::ostream& os, const FatBinary& fatbinary) {
  for (const Binary& binary : fatbinary) {
    os << binary << "\n\n";
  }

  return os;
}

}
}
