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

#include "jni/lief/pe/CodeIntegrity.hpp"
#include "jni/log.hpp"
#include "jni/jni_utils.hpp"

namespace lief_jni::pe {

int CodeIntegrity::register_natives(JNIEnv* env) {
  static const std::array NATIVE_METHODS {
    make(
      "getFlags",
      "()S",
      jni_get_flags
    ),

    make(
      "getCatalog",
      "()S",
      jni_get_catalog
    ),

    make(
      "getCatalogOffset",
      "()I",
      jni_get_catalog_offset
    ),

    make(
      "getReserved",
      "()I",
      jni_get_reserved
    ),

    make_destroy(
      &jni_destroy
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
