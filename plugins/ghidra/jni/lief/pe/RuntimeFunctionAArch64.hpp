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

#include "jni/lief/pe/ExceptionInfo.hpp"

#include <LIEF/PE/exceptions_info/RuntimeFunctionAArch64.hpp>

namespace lief_jni::pe {

class RuntimeFunctionAArch64 : public ExceptionInfo {
  public:
  using lief_t = LIEF::PE::RuntimeFunctionAArch64;
  using JNI::create;

  using ExceptionInfo::ExceptionInfo;

  static constexpr jni::Class kClass {
    "lief/pe/RuntimeFunctionAArch64",
    jni::Constructor{ jlong{} },
  };

  static int register_natives(JNIEnv* env);

  static auto jni_get_length(JNIEnv* env, jobject thiz) {
    return (jlong)from_jni(thiz)->cast<lief_t>().length();
  }

  static void jni_destroy(JNIEnv* env, jobject thiz) {
    destroy(thiz);
  }
};
}
