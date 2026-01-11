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

#include "jni/lief/pe/LoadConfigurations/CHPEMetadata/Metadata.hpp"
#include <LIEF/PE/LoadConfigurations/CHPEMetadata/MetadataX86.hpp>

namespace lief_jni::pe {

class CHPEMetadataX86 : public CHPEMetadata {
  public:
  using lief_t = LIEF::PE::CHPEMetadataX86;
  using JNI::create;

  using CHPEMetadata::CHPEMetadata;

  static constexpr jni::Class kClass {
    "lief/pe/CHPEMetadataX86",
    jni::Constructor{ jlong{} },
  };

  static int register_natives(JNIEnv* env);

  static void jni_destroy(JNIEnv* env, jobject thiz) {
    destroy(thiz);
  }
};
}
