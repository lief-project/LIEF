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
#include "jni/mirror.hpp"
#include "jni/canbe_unique.hpp"

#include <LIEF/PE/LoadConfigurations/CHPEMetadata/Metadata.hpp>

namespace lief_jni::pe {

class CHPEMetadata : public JNI<CHPEMetadata, canbe_unique<LIEF::PE::CHPEMetadata>> {
  public:
  using JNI::JNI;
  using lief_t = LIEF::PE::CHPEMetadata;

  static constexpr jni::Class kClass {
    "lief/pe/CHPEMetadata",
    jni::Constructor{ jlong{} },
    jni::Field { "impl", jlong{}, }
  };

  static jobject create(lief_t& impl);

  static jint jni_get_version(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->impl().version();
  }

  static int register_natives(JNIEnv* env);

  static void jni_destroy(JNIEnv* env, jobject thiz) {
    destroy(thiz);
  }
};
}
