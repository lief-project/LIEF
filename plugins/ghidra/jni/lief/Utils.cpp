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
#include <array>

#include "jni/lief/Utils.hpp"
#include "jni/log.hpp"
#include "jni/jni_utils.hpp"

thread_local int jni::ThreadGuard::thread_guard_count_ = 0;
thread_local jni::ThreadLocalGuardDestructor jni::ThreadGuard::thread_local_guard_destructor{};

namespace lief_jni {

int Utils::register_natives(JNIEnv* env) {
  static const std::array NATIVE_METHODS {
    make(
      "isExtended",
      "()Z",
      &jni_is_extended
    ),
    make(
      "getExtendedVersionInfo",
      "()Ljava/lang/String;",
      &jni_get_extended_version_info
    ),
    make(
      "getExtendedVersion",
      "()Llief/Utils$Version;",
      &jni_get_extended_version
    ),
    make(
      "getVersion",
      "()Llief/Utils$Version;",
      &jni_get_version
    ),
  };

  env->RegisterNatives(
    jni::StaticRef<kClass>{}.GetJClass(),
    NATIVE_METHODS.data(), NATIVE_METHODS.size()
  );

  GHIDRA_DEBUG("'{}' registered", kClass.name_);
  return JNI_OK;
}

}
