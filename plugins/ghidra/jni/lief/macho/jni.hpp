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
#include <jni.h>
#include "jni/lief/macho/Header.hpp"
#include "jni/lief/macho/Binary.hpp"
#include "jni/lief/macho/FatBinary.hpp"
#include "jni/lief/macho/Utils.hpp"

namespace lief_jni::macho {

inline void register_natives(JNIEnv* env) {
  Header::register_natives(env);
  Binary::register_natives(env);
  FatBinary::register_natives(env);
  Utils::register_natives(env);
}
}
