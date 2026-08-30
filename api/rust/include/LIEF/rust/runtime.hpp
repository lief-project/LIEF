/* Copyright 2022 - 2026 R. Thomas
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
#pragma once
#include "LIEF/rust/helpers.hpp"

#include "LIEF/rust/runtime/Assembler.hpp"
#include "LIEF/rust/runtime/Disassembler.hpp"
#include "LIEF/rust/runtime/Host.hpp"
#include "LIEF/rust/runtime/Memory.hpp"
#include "LIEF/rust/runtime/MemoryLayout.hpp"
#include "LIEF/rust/runtime/Module.hpp"
#include "LIEF/rust/runtime/Process.hpp"
#include "LIEF/rust/runtime/android/Host.hpp"
#include "LIEF/rust/runtime/android/Module.hpp"
#include "LIEF/rust/runtime/android/Process.hpp"
#include "LIEF/rust/runtime/android/Property.hpp"
#include "LIEF/rust/runtime/linux/Host.hpp"
#include "LIEF/rust/runtime/linux/Module.hpp"
#include "LIEF/rust/runtime/linux/Process.hpp"
#include "LIEF/rust/runtime/osx/Host.hpp"
#include "LIEF/rust/runtime/osx/Module.hpp"
#include "LIEF/rust/runtime/osx/Process.hpp"
#include "LIEF/rust/runtime/windows/Host.hpp"
#include "LIEF/rust/runtime/windows/Module.hpp"

inline bool runtime_enabled() {
  return LIEF::runtime::is_enabled();
}

inline auto runtime_platform() {
  return to_int(LIEF::runtime::platform());
}

inline auto runtime_arch() {
  return to_int(LIEF::runtime::arch());
}
