/* Copyright 2024 R. Thomas
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

#include <cstdint>
#include <vector>
#include "LIEF/rust/Stream.hpp"
#include "LIEF/BinaryStream/VectorStream.hpp"

std::unique_ptr<RustStream> RustStream::from_rust(uint8_t* buffer, size_t size) {
  std::vector<uint8_t> vector{buffer, buffer + size};
  auto vstream = std::make_unique<LIEF::VectorStream>(std::move(vector));
  return std::make_unique<RustStream>(std::move(vstream));
}
