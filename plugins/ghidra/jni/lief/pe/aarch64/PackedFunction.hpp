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

#include <jni_bind.h>

#include "jni/lief/pe/RuntimeFunctionAArch64.hpp"

#include <LIEF/PE/exceptions_info/AArch64/PackedFunction.hpp>

namespace lief_jni::pe::aarch64 {

class PackedFunction : public RuntimeFunctionAArch64 {
  public:
  using lief_t = LIEF::PE::unwind_aarch64::PackedFunction;
  using JNI::create;

  using RuntimeFunctionAArch64::RuntimeFunctionAArch64;

  static constexpr jni::Class kClass {
    "lief/pe/aarch64/PackedFunction",
    jni::Constructor{ jlong{} },
  };

  static int register_natives(JNIEnv* env);

  static void jni_destroy(JNIEnv* env, jobject thiz) {
    destroy(thiz);
  }
};
}
