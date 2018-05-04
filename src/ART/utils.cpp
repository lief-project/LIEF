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
#include <fstream>
#include <map>

#include "LIEF/ART/utils.hpp"
#include "LIEF/ART/Structures.hpp"

namespace LIEF {
namespace ART {
bool is_art(const std::string& file) {
  if (std::ifstream ifs{file, std::ios::in | std::ios::binary}) {

    char magic[sizeof(ART::art_magic)];

    ifs.seekg(0, std::ios::beg);
    ifs.read(magic, sizeof(magic));

    return std::equal(
        std::begin(magic),
        std::end(magic),
        std::begin(ART::art_magic));

  }

  return false;
}

bool is_art(const std::vector<uint8_t>& raw) {
  if (raw.size() < sizeof(ART::art_magic)) {
    return false;
  }

  char magic[sizeof(ART::art_magic)];
  std::copy(
    reinterpret_cast<const uint8_t*>(raw.data()),
    reinterpret_cast<const uint8_t*>(raw.data()) + sizeof(ART::art_magic),
    magic);

  return std::equal(std::begin(magic), std::end(magic), std::begin(ART::art_magic));
}

art_version_t version(const std::string& file) {
  if (not is_art(file)) {
    return 0;
  }

  if (std::ifstream ifs{file, std::ios::in | std::ios::binary}) {

    char version[4];

    ifs.seekg(sizeof(ART::art_magic), std::ios::beg);
    ifs.read(version, sizeof(version));

    if (std::all_of(version, version + sizeof(version) - 1, ::isdigit)) {
      return static_cast<art_version_t>(std::stoul(version));
    }
    return 0;

  }
  return 0;

}

art_version_t version(const std::vector<uint8_t>& raw) {
  if (raw.size() < 8) {
    return 0;
  }

  char version[4];
  std::copy(
    reinterpret_cast<const uint8_t*>(raw.data()) + sizeof(ART::art_magic),
    reinterpret_cast<const uint8_t*>(raw.data()) + sizeof(ART::art_magic) + sizeof(version) + 1,
    version);


  if (std::all_of(version, version + sizeof(version) - 1, ::isdigit)) {
    return static_cast<art_version_t>(std::stoul(version));
  }

  return 0;
}

LIEF::Android::ANDROID_VERSIONS android_version(art_version_t version) {
  static const std::map<art_version_t, LIEF::Android::ANDROID_VERSIONS> oat2android {
    { 17, LIEF::Android::ANDROID_VERSIONS::VERSION_601 },
    { 29, LIEF::Android::ANDROID_VERSIONS::VERSION_700 },
    { 30, LIEF::Android::ANDROID_VERSIONS::VERSION_712 },
    { 44, LIEF::Android::ANDROID_VERSIONS::VERSION_800 },
    { 46, LIEF::Android::ANDROID_VERSIONS::VERSION_810 },

  };
  auto   it  = oat2android.lower_bound(version);
  return it == oat2android.end() ? LIEF::Android::ANDROID_VERSIONS::VERSION_UNKNOWN : it->second;
}


}
}
